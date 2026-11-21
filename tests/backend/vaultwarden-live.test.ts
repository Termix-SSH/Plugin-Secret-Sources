/**
 * Live test against a real Vaultwarden. Skipped unless these are set (values
 * for the Testing host are in /opt/termix-test/README.md):
 *   TERMIX_VW_URL            http://100.78.68.100:8097
 *   TERMIX_VW_CLIENT_ID      alice's personal API key client id
 *   TERMIX_VW_CLIENT_SECRET  and its secret
 * Accounts: vwalice@termix.test / AliceMaster123! (PBKDF2, owns org Ops with
 * db-1) and vwbob@termix.test / BobMaster123! (Argon2id, not in Ops).
 */
import { describe, expect, it } from "vitest";
import { createMockCtx } from "@termix-ssh/plugin-sdk/testing";
import { createVaultSessions } from "../../src/backend/bitwarden/vault-sessions.js";
import { bitwardenVaultProvider } from "../../src/backend/providers/bitwarden-vault.js";
import { parseBitwardenCliReference } from "../../src/backend/providers/bitwarden-cli.js";
import { manifest } from "./helpers.js";

const URL_ = process.env.TERMIX_VW_URL ?? "";
const live = describe.skipIf(!URL_);

function setUp() {
  const mock = createMockCtx({
    sandbox: true,
    pluginId: manifest.id,
    manifest,
    capabilities: manifest.capabilities,
    actor: "alice",
    fetch: ((url: string, init?: Record<string, unknown>) =>
      fetch(url, {
        method: init?.method as string | undefined,
        headers: init?.headers as Record<string, string> | undefined,
        body: init?.body as string | undefined,
      })) as never,
  });
  const sessions = createVaultSessions(mock.ctx);
  const source = { id: "src-vw", baseUrl: URL_, credential: "" };
  const target = { baseUrl: URL_, allowedPrivateHosts: [] };
  const resolve = (user: string, reference: string) =>
    bitwardenVaultProvider.resolve(
      mock.ctx.fetch,
      {
        ...target,
        credential: "",
        vault: () => sessions.open(source, user, target),
      },
      parseBitwardenCliReference(reference)!,
    );
  return { sessions, source, target, resolve };
}

live("Vaultwarden, each user with their own vault", () => {
  it("unlocks with email and master password and reads personal and org items", async () => {
    const { sessions, source, target, resolve } = setUp();
    await expect(resolve("alice", "bw://web-1/password")).rejects.toThrow(
      /locked/,
    );
    const status = await sessions.unlock(source, "alice", target, {
      method: "password",
      email: "vwalice@termix.test",
      password: "AliceMaster123!",
    });
    expect(status).toMatchObject({
      unlocked: true,
      email: "vwalice@termix.test",
    });
    expect(await resolve("alice", "bw://web-1/password")).toBe(
      "alice-web-pass",
    );
    expect(await resolve("alice", "bw://web-1/sudo")).toBe("alice-sudo");
    expect(await resolve("alice", "bw://web-1/totp")).toMatch(/^\d{6}$/);
    expect(await resolve("alice", "bw://db-1/password")).toBe("org-db-pass");
  });

  it("keeps each user to their own vault, with Argon2id", async () => {
    const { sessions, source, target, resolve } = setUp();
    await sessions.unlock(source, "bob", target, {
      method: "password",
      email: "vwbob@termix.test",
      password: "BobMaster123!",
    });
    expect(await resolve("bob", "bw://web-1/password")).toBe("bob-web-pass");
    await expect(resolve("bob", "bw://db-1/password")).rejects.toThrow(
      /not found/,
    );
    await expect(resolve("alice", "bw://web-1/password")).rejects.toThrow(
      /locked/,
    );
  });

  it.skipIf(!process.env.TERMIX_VW_CLIENT_ID)(
    "unlocks with a personal API key and checks the master password",
    async () => {
      const { sessions, source, target, resolve } = setUp();
      const apiKey = {
        method: "apikey" as const,
        clientId: process.env.TERMIX_VW_CLIENT_ID ?? "",
        clientSecret: process.env.TERMIX_VW_CLIENT_SECRET ?? "",
      };
      await expect(
        sessions.unlock(source, "alice", target, {
          ...apiKey,
          password: "wrong",
        }),
      ).rejects.toThrow(/Wrong master password/);
      await sessions.unlock(source, "alice", target, {
        ...apiKey,
        password: "AliceMaster123!",
      });
      expect(await resolve("alice", "bw://db-1/username")).toBe("postgres");
    },
  );

  it("refuses a wrong password", async () => {
    const { sessions, source, target } = setUp();
    await expect(
      sessions.unlock(source, "alice", target, {
        method: "password",
        email: "vwalice@termix.test",
        password: "nope",
      }),
    ).rejects.toThrow(/Sign in failed/);
  });
});
