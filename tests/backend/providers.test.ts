import { createCipheriv, createHmac, randomBytes } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  bitwardenEndpoints,
  bitwardenSmProvider,
  decryptEncString,
  deriveShareableKey,
  parseAccessToken,
  parseBitwardenSmReference,
  type SymmetricKey,
} from "../../src/backend/providers/bitwarden-sm.js";
import {
  infisicalProvider,
  parseInfisicalReference,
} from "../../src/backend/providers/infisical.js";
import {
  parseVaultReference,
  vaultProvider,
} from "../../src/backend/providers/hashicorp-vault.js";
import {
  bitwardenCliProvider,
  parseBitwardenCliReference,
} from "../../src/backend/providers/bitwarden-cli.js";

function json(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  } as unknown as Response;
}

const source = (credential: string, baseUrl = "https://secrets.test") => ({
  baseUrl,
  credential,
  allowedPrivateHosts: [],
});

describe("Infisical", () => {
  it("parses references with and without a folder", () => {
    expect(parseInfisicalReference("infisical://p1/prod/DB_PASS")).toEqual({
      projectId: "p1",
      environment: "prod",
      path: "/",
      name: "DB_PASS",
    });
    expect(
      parseInfisicalReference("infisical://p1/dev/apps/api/TOKEN")?.path,
    ).toBe("/apps/api");
    expect(parseInfisicalReference("infisical://p1/prod")).toBeNull();
  });

  it("signs in with universal auth and reads the raw secret", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(json({ accessToken: "at" }))
      .mockResolvedValueOnce(json({ secret: { secretValue: "hunter2" } }));
    const value = await infisicalProvider.resolve(
      fetch,
      source(JSON.stringify({ clientId: "id", clientSecret: "sec" })),
      parseInfisicalReference("infisical://p1/prod/apps/DB_PASS")!,
    );
    expect(value).toBe("hunter2");
    expect(fetch.mock.calls[0][0]).toBe(
      "https://secrets.test/api/v1/auth/universal-auth/login",
    );
    const url = new URL(fetch.mock.calls[1][0]);
    expect(url.pathname).toBe("/api/v3/secrets/raw/DB_PASS");
    expect(url.searchParams.get("workspaceId")).toBe("p1");
    expect(url.searchParams.get("environment")).toBe("prod");
    expect(url.searchParams.get("secretPath")).toBe("/apps");
    expect(fetch.mock.calls[1][1].headers.Authorization).toBe("Bearer at");
  });
});

describe("HashiCorp Vault", () => {
  it("parses vault://mount/path#key", () => {
    expect(parseVaultReference("vault://secret/apps/db#password")).toEqual({
      mount: "secret",
      path: "apps/db",
      key: "password",
    });
    expect(parseVaultReference("vault://secret/apps/db")).toBeNull();
  });

  it("reads KV v2 with a token and a namespace", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(json({ data: { data: { password: "pw" } } }));
    const value = await vaultProvider.resolve(
      fetch,
      source(JSON.stringify({ token: "hvs.x", namespace: "team" })),
      parseVaultReference("vault://secret/apps/db#password")!,
    );
    expect(value).toBe("pw");
    expect(fetch.mock.calls[0][0]).toBe(
      "https://secrets.test/v1/secret/data/apps/db",
    );
    expect(fetch.mock.calls[0][1].headers).toMatchObject({
      "X-Vault-Token": "hvs.x",
      "X-Vault-Namespace": "team",
    });
  });

  it("falls back to KV v1, and logs in with AppRole", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(json({ auth: { client_token: "t1" } }))
      .mockResolvedValueOnce(json({}, 404))
      .mockResolvedValueOnce(json({ data: { password: "old" } }));
    const value = await vaultProvider.resolve(
      fetch,
      source(JSON.stringify({ roleId: "r", secretId: "s" })),
      parseVaultReference("vault://kv/db#password")!,
    );
    expect(value).toBe("old");
    expect(fetch.mock.calls[0][0]).toBe(
      "https://secrets.test/v1/auth/approle/login",
    );
    expect(fetch.mock.calls[2][0]).toBe("https://secrets.test/v1/kv/db");
    expect(fetch.mock.calls[2][1].headers["X-Vault-Token"]).toBe("t1");
  });
});

describe("Bitwarden CLI", () => {
  it("finds an item by name and reads a field", async () => {
    const fetch = vi.fn().mockResolvedValueOnce(
      json({
        success: true,
        data: {
          data: [
            { id: "1", name: "prod-db-old" },
            {
              id: "2",
              name: "prod-db",
              login: { username: "root", password: "pw" },
              fields: [{ name: "Port", value: "5432" }],
            },
          ],
        },
      }),
    );
    expect(
      await bitwardenCliProvider.resolve(
        fetch,
        source("", "http://localhost:8087"),
        parseBitwardenCliReference("bw://prod-db/password")!,
      ),
    ).toBe("pw");

    fetch.mockResolvedValueOnce(
      json({
        success: true,
        data: {
          data: [
            {
              id: "2",
              name: "prod-db",
              fields: [{ name: "Port", value: "5432" }],
            },
          ],
        },
      }),
    );
    expect(
      await bitwardenCliProvider.resolve(
        fetch,
        source("", "http://localhost:8087"),
        parseBitwardenCliReference("bw://prod-db/port")!,
      ),
    ).toBe("5432");
  });

  it("refuses a locked vault in the test", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(
        json({ success: true, data: { template: { status: "locked" } } }),
      );
    await expect(
      bitwardenCliProvider.test(fetch, source("", "http://localhost:8087")),
    ).rejects.toThrow(/locked/);
  });
});

function encrypt(plain: Buffer, key: SymmetricKey): string {
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-256-cbc", key.enc, iv);
  const data = Buffer.concat([cipher.update(plain), cipher.final()]);
  const mac = createHmac("sha256", key.mac)
    .update(Buffer.concat([iv, data]))
    .digest();
  return `2.${iv.toString("base64")}|${data.toString("base64")}|${mac.toString("base64")}`;
}

// HKDF expand written out by hand, to check deriveShareableKey against it.
function manualShareableKey(secret: Buffer, name: string, info: string) {
  const prk = createHmac("sha256", `bitwarden-${name}`).update(secret).digest();
  const t1 = createHmac("sha256", prk)
    .update(Buffer.concat([Buffer.from(info), Buffer.from([1])]))
    .digest();
  const t2 = createHmac("sha256", prk)
    .update(Buffer.concat([t1, Buffer.from(info), Buffer.from([2])]))
    .digest();
  return { enc: t1, mac: t2 };
}

describe("Bitwarden Secrets Manager", () => {
  const id = "11111111-2222-3333-4444-555555555555";
  const tokenKey = randomBytes(16);
  const accessToken = `0.${id}.clientsecret:${tokenKey.toString("base64")}`;

  it("parses access tokens and references", () => {
    expect(parseAccessToken(accessToken)).toMatchObject({
      id,
      clientSecret: "clientsecret",
    });
    expect(parseAccessToken("nope")).toBeNull();
    expect(parseBitwardenSmReference(`bws://${id}`)).toEqual({ secretId: id });
    expect(parseBitwardenSmReference("bws://not-a-uuid")).toBeNull();
  });

  it("derives keys the way Bitwarden does", () => {
    const derived = deriveShareableKey(
      tokenKey,
      "accesstoken",
      "sm-access-token",
    );
    const manual = manualShareableKey(
      tokenKey,
      "accesstoken",
      "sm-access-token",
    );
    expect(derived.enc.equals(manual.enc)).toBe(true);
    expect(derived.mac.equals(manual.mac)).toBe(true);
  });

  it("rejects a changed cipher text", () => {
    const key = { enc: randomBytes(32), mac: randomBytes(32) };
    const enc = encrypt(Buffer.from("x"), key);
    const [head, , mac] = enc.split("|");
    const tampered = `${head}|${randomBytes(16).toString("base64")}|${mac}`;
    expect(() => decryptEncString(tampered, key)).toThrow(/integrity/);
  });

  it("logs in, unlocks the organization key and decrypts the secret", async () => {
    const orgKey = randomBytes(64);
    const tokenSym = deriveShareableKey(
      tokenKey,
      "accesstoken",
      "sm-access-token",
    );
    const payload = encrypt(
      Buffer.from(JSON.stringify({ encryptionKey: orgKey.toString("base64") })),
      tokenSym,
    );
    const value = encrypt(Buffer.from("db-password"), {
      enc: orgKey.subarray(0, 32),
      mac: orgKey.subarray(32),
    });
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(
        json({ access_token: "jwt", encrypted_payload: payload }),
      )
      .mockResolvedValueOnce(json({ id, value }));

    const result = await bitwardenSmProvider.resolve(
      fetch,
      source(accessToken, "https://vault.bitwarden.com"),
      { secretId: id },
    );
    expect(result).toBe("db-password");
    expect(fetch.mock.calls[0][0]).toBe(
      "https://identity.bitwarden.com/connect/token",
    );
    const form = new URLSearchParams(fetch.mock.calls[0][1].body);
    expect(form.get("client_id")).toBe(id);
    expect(form.get("scope")).toBe("api.secrets");
    expect(fetch.mock.calls[1][0]).toBe(
      `https://api.bitwarden.com/secrets/${id}`,
    );
  });

  it("uses /identity and /api on a self-hosted server", () => {
    expect(bitwardenEndpoints("https://bw.example.com/")).toEqual({
      identity: "https://bw.example.com/identity",
      api: "https://bw.example.com/api",
    });
    expect(bitwardenEndpoints("https://vault.bitwarden.eu").api).toBe(
      "https://api.bitwarden.eu",
    );
  });
});
