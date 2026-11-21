import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import {
  checkKdf,
  makeMasterKey,
  totpCode,
  unwrapUserKey,
} from "../../src/backend/bitwarden/vault-crypto.js";
import {
  decryptItems,
  findItem,
  readField,
  vaultPickItems,
} from "../../src/backend/bitwarden/vault-items.js";
import {
  parseTokenAnswer,
  ssoCodeFrom,
  startSso,
} from "../../src/backend/bitwarden/vault-client.js";
import { sessionHours } from "../../src/backend/bitwarden/vault-sessions.js";
import { startServer, type TestServer } from "./helpers.js";
import {
  enc,
  key64,
  loginCipher,
  makeAccount,
  wrapOrgKey,
  type TestAccount,
} from "./bitwarden-fixture.js";

describe("vault crypto", () => {
  it("makes RFC 6238 TOTP codes", () => {
    // RFC 6238 SHA-1 vector: secret "12345678901234567890", 8 digits.
    const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    expect(totpCode(`otpauth://totp/x?secret=${secret}&digits=8`, 59_000)).toBe(
      "94287082",
    );
    expect(totpCode(secret, 1111111109_000)).toBe("081804");
  });

  it("refuses key derivation weaker than the official clients allow", () => {
    expect(() => checkKdf({ kdf: 0, iterations: 1000 })).toThrow(/too few/);
    expect(() =>
      checkKdf({ kdf: 1, iterations: 3, memory: 4, parallelism: 1 }),
    ).toThrow(/too weak/);
    expect(() => checkKdf({ kdf: 7, iterations: 1 })).toThrow(/Unsupported/);
  });

  it("opens the user key and says when the master password is wrong", async () => {
    const account = await makeAccount("A@Example.com", "pw");
    const right = await makeMasterKey("pw", "a@example.com", account.kdf);
    expect(unwrapUserKey(account.encryptedUserKey, right)).toEqual(
      account.userKey,
    );
    const wrong = await makeMasterKey("nope", "a@example.com", account.kdf);
    expect(() => unwrapUserKey(account.encryptedUserKey, wrong)).toThrow(
      "Wrong master password",
    );
  });

  it("derives Argon2id master keys", async () => {
    const kdf = { kdf: 1, iterations: 2, memory: 16, parallelism: 1 };
    const account = await makeAccount("b@example.com", "pw", kdf);
    const key = await makeMasterKey("pw", "b@example.com", kdf);
    expect(unwrapUserKey(account.encryptedUserKey, key)).toEqual(
      account.userKey,
    );
  });
});

function vaultFor(account: TestAccount) {
  const userKey = key64(account.userKey);
  const orgKey = randomBytes(64);
  const itemKey = randomBytes(64);
  return {
    userKey: account.userKey,
    sync: {
      profile: {
        privateKey: account.encryptedPrivateKey,
        organizations: [
          { id: "org-1", key: wrapOrgKey(orgKey, account.publicKey) },
        ],
      },
      folders: [{ id: "f-1", name: enc("Servers", userKey) }],
      ciphers: [
        {
          id: "11111111-1111-1111-1111-111111111111",
          folderId: "f-1",
          ...loginCipher(userKey, {
            name: "web-1",
            username: "deploy",
            password: "web-pass",
            custom: { Sudo: "sudo-pass" },
          }),
        },
        {
          id: "22222222-2222-2222-2222-222222222222",
          organizationId: "org-1",
          key: enc(itemKey, key64(orgKey)),
          ...loginCipher(key64(itemKey), {
            name: "db-1",
            username: "postgres",
            password: "db-pass",
          }),
        },
        {
          id: "33333333-3333-3333-3333-333333333333",
          deletedDate: "2026-01-01",
          ...loginCipher(userKey, { name: "gone", password: "x" }),
        },
        {
          id: "44444444-4444-4444-4444-444444444444",
          type: 5,
          name: enc("ssh-1", userKey),
          sshKey: { privateKey: enc("-----BEGIN KEY-----", userKey) },
        },
      ],
    },
  } as never;
}

describe("vault items", () => {
  it("reads personal, organization and SSH key items, skipping trash", async () => {
    const vault = vaultFor(await makeAccount("a@example.com", "pw"));
    const items = decryptItems(vault);
    expect(items.map((item) => item.name).sort()).toEqual([
      "db-1",
      "ssh-1",
      "web-1",
    ]);
    expect(readField(findItem(items, "WEB-1"), "password")).toBe("web-pass");
    expect(readField(findItem(items, "web-1"), "sudo")).toBe("sudo-pass");
    expect(readField(findItem(items, "db-1"), "username")).toBe("postgres");
    expect(
      readField(
        findItem(items, "22222222-2222-2222-2222-222222222222"),
        "password",
      ),
    ).toBe("db-pass");
    expect(readField(findItem(items, "ssh-1"), "privatekey")).toContain(
      "BEGIN",
    );
    expect(() => findItem(items, "gone")).toThrow(/not found/);
    expect(() => readField(findItem(items, "web-1"), "nope")).toThrow(
      /not found/,
    );
  });

  it("lists logins for the picker by id, with folders", async () => {
    const vault = vaultFor(await makeAccount("a@example.com", "pw"));
    const picked = vaultPickItems(vault, decryptItems(vault), "web");
    expect(picked).toEqual([
      {
        id: "11111111-1111-1111-1111-111111111111",
        name: "web-1",
        folder: "Servers",
        username: "bw://11111111-1111-1111-1111-111111111111/username",
        password: "bw://11111111-1111-1111-1111-111111111111/password",
      },
    ]);
  });
});

describe("vault client", () => {
  it("reads the token answer in either case and prefers the unlock options", () => {
    const answer = parseTokenAnswer({
      access_token: "a.eyJlbWFpbCI6InhAeS56In0.c",
      expires_in: 60,
      key: "2.old",
      kdf: 0,
      kdfIterations: 600000,
      userDecryptionOptions: {
        masterPasswordUnlock: {
          kdf: { kdfType: 1, iterations: 3, memory: 64, parallelism: 4 },
          masterKeyEncryptedUserKey: "2.new",
          salt: "x@y.z",
        },
      },
    });
    expect(answer).toMatchObject({
      key: "2.new",
      salt: "x@y.z",
      kdf: { kdf: 1, iterations: 3, memory: 64, parallelism: 4 },
      refreshToken: null,
    });
    const fallback = parseTokenAnswer({
      access_token: "a.eyJlbWFpbCI6InhAeS56In0.c",
      key: "2.k",
      kdf: 0,
      kdfIterations: 600000,
    });
    expect(fallback).toMatchObject({ key: "2.k", salt: "x@y.z" });
  });

  it("starts SSO on the CLI client and only takes back its own state", () => {
    const start = startSso("https://vault.example.com", "acme");
    const url = new URL(start.url);
    expect(url.pathname).toBe("/identity/connect/authorize");
    expect(url.searchParams.get("client_id")).toBe("cli");
    expect(url.searchParams.get("redirect_uri")).toBe("http://localhost:8065");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("domain_hint")).toBe("acme");
    expect(
      ssoCodeFrom(
        `http://localhost:8065/?code=abc&state=${start.state}`,
        start.state,
      ),
    ).toBe("abc");
    expect(() =>
      ssoCodeFrom("http://localhost:8065/?code=abc&state=other", start.state),
    ).toThrow(/different sign in/);
    expect(() => ssoCodeFrom("not a url", start.state)).toThrow(/full address/);
  });

  it("keeps session length within bounds", () => {
    expect(sessionHours("")).toBe(8);
    expect(sessionHours(JSON.stringify({ sessionHours: "24" }))).toBe(24);
    expect(sessionHours(JSON.stringify({ sessionHours: "99999" }))).toBe(720);
  });
});

function json(body: unknown, status = 200): Response {
  return {
    ok: status < 400,
    status,
    json: async () => body,
  } as unknown as Response;
}

/** A tiny Bitwarden server for one account with a password login. */
function fakeServer(
  account: TestAccount,
  options: { twoFactor?: string } = {},
) {
  const calls: string[] = [];
  const fetch = async (url: string, init?: { body?: string }) => {
    const path = new URL(url).pathname;
    calls.push(path);
    if (path === "/identity/accounts/prelogin") {
      return json({ kdf: 0, kdfIterations: account.kdf.iterations });
    }
    if (path === "/identity/connect/token") {
      const form = new URLSearchParams(init?.body ?? "");
      if (form.get("password") !== account.passwordHash) {
        return json({ error_description: "invalid_username_or_password" }, 400);
      }
      if (
        options.twoFactor &&
        form.get("twoFactorToken") !== options.twoFactor
      ) {
        return json(
          {
            error_description: "Two factor required.",
            TwoFactorProviders: [0],
          },
          400,
        );
      }
      return json({
        access_token: `h.${Buffer.from(JSON.stringify({ email: account.email })).toString("base64url")}.s`,
        expires_in: 3600,
        refresh_token: "refresh",
        Key: account.encryptedUserKey,
        Kdf: 0,
        KdfIterations: account.kdf.iterations,
      });
    }
    if (path === "/api/sync") {
      return json((vaultFor(account) as { sync: unknown }).sync);
    }
    if (path === "/api/config") return json({});
    return json({}, 404);
  };
  return { fetch, calls };
}

let server: TestServer;

afterEach(async () => {
  await server?.close();
});

describe("per-user vault routes", () => {
  async function withVault(options: { twoFactor?: string } = {}) {
    const account = await makeAccount("alice@example.com", "master");
    const fake = fakeServer(account, options);
    server = await startServer({ fetch: fake.fetch as never });
    const created = await server.request("POST", "/", {
      body: {
        name: "Vaultwarden",
        kind: "bitwarden-vault",
        baseUrl: "https://vault.example.com",
        token: JSON.stringify({ sessionHours: "2" }),
        shared: false,
      },
    });
    expect(created.status).toBe(200);
    return { id: created.body.source.id as string, fake };
  }

  it("is locked until the user unlocks it, then resolves with their vault", async () => {
    const { id } = await withVault();
    expect((await server.request("GET", `/${id}/session`)).body).toMatchObject({
      unlocked: false,
    });
    const locked = await server.request("POST", "/test-reference", {
      body: { reference: "bw://web-1/password" },
    });
    expect(locked.body.status).toBe("locked");
    expect((await server.request("GET", `/${id}/items`)).status).toBe(409);

    const unlocked = await server.request("POST", `/${id}/session`, {
      body: {
        method: "password",
        email: "alice@example.com",
        password: "master",
      },
    });
    expect(unlocked.status).toBe(200);
    expect(unlocked.body).toMatchObject({
      unlocked: true,
      email: "alice@example.com",
      method: "password",
    });
    expect(unlocked.body.expiresAt - Date.now()).toBeLessThanOrEqual(
      2 * 3_600_000,
    );

    const found = await server.request("POST", "/test-reference", {
      body: { reference: "bw://db-1/password" },
    });
    expect(found.body).toMatchObject({ ok: true, status: "found" });
    const items = await server.request("GET", `/${id}/items?search=web`);
    expect(items.body.items).toHaveLength(1);

    const resolve = server.mock.auth.secretResolvers.get("bw");
    expect(await resolve?.("user-1", "bw://web-1/password")).toBe("web-pass");

    // Another user does not get this user's vault.
    await expect(resolve?.("user-2", "bw://web-1/password")).rejects.toThrow(
      /no secret source|locked/,
    );

    expect((await server.request("DELETE", `/${id}/session`)).status).toBe(200);
    await expect(
      resolve?.("user-1", "bw://web-1/password"),
    ).rejects.toMatchObject({ code: "unlock-required" });
  });

  it("asks for a two-step code and passes it on", async () => {
    const { id } = await withVault({ twoFactor: "123456" });
    const first = await server.request("POST", `/${id}/session`, {
      body: {
        method: "password",
        email: "alice@example.com",
        password: "master",
      },
    });
    expect(first.status).toBe(400);
    expect(first.body.twoFactor).toEqual([0]);
    const second = await server.request("POST", `/${id}/session`, {
      body: {
        method: "password",
        email: "alice@example.com",
        password: "master",
        twoFactorProvider: 0,
        twoFactorCode: "123456",
      },
    });
    expect(second.status).toBe(200);
  });

  it("refuses incomplete bodies and stops guessing after ten misses", async () => {
    const { id } = await withVault();
    expect(
      (
        await server.request("POST", `/${id}/session`, {
          body: { method: "sso" },
        })
      ).status,
    ).toBe(400);
    for (let i = 0; i < 10; i++) {
      const miss = await server.request("POST", `/${id}/session`, {
        body: { method: "password", email: "alice@example.com", password: "x" },
      });
      expect(miss.status).toBe(400);
      expect(miss.body.error).toMatch(/Sign in failed/);
    }
    const blocked = await server.request("POST", `/${id}/session`, {
      body: {
        method: "password",
        email: "alice@example.com",
        password: "master",
      },
    });
    expect(blocked.status).toBe(429);
  });

  it("starts SSO and refuses a pasted address from another sign in", async () => {
    const { id } = await withVault();
    const start = await server.request("POST", `/${id}/session/sso`);
    expect(start.body.url).toContain("/identity/connect/authorize?");
    const res = await server.request("POST", `/${id}/session`, {
      body: {
        method: "sso",
        redirect: "http://localhost:8065/?code=x&state=wrong",
        password: "master",
      },
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/different sign in/);
  });

  it("only serves session routes for per-user sources the caller can see", async () => {
    const { id } = await withVault();
    expect(
      (await server.request("GET", `/${id}/session`, { user: "user-2" }))
        .status,
    ).toBe(404);
    const op = await server.request("POST", "/", {
      body: { name: "op", baseUrl: "https://connect", token: "t" },
    });
    expect(
      (await server.request("GET", `/${op.body.source.id}/session`)).status,
    ).toBe(400);
  });

  it("locks everyone when the source is deleted", async () => {
    const { id } = await withVault();
    await server.request("POST", `/${id}/session`, {
      body: {
        method: "password",
        email: "alice@example.com",
        password: "master",
      },
    });
    expect(await server.mock.ctx.kv.get(`sessions:${id}`)).toEqual(["user-1"]);
    await server.request("DELETE", `/${id}`);
    expect(await server.mock.ctx.kv.get(`sessions:${id}`)).toBeNull();
  });
});
