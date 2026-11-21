import type { PluginContext } from "@termix-ssh/plugin-sdk/backend";
import { credentialFields } from "../providers/types.js";
import {
  fetchSync,
  loginWithApiKey,
  loginWithPassword,
  loginWithSsoCode,
  newDeviceId,
  refreshAccessToken,
  ssoCodeFrom,
  startSso,
  unlockUserKey,
  VaultLoginError,
  type TokenAnswer,
  type VaultSync,
  type VaultTarget,
} from "./vault-client.js";
import type { OpenVault } from "./vault-items.js";

/**
 * Each Termix user's own unlocked Bitwarden or Vaultwarden session for a
 * source. The user key is kept in ctx.secrets for that user only, until the
 * session runs out, then the user unlocks again. Access tokens live in memory
 * and are renewed with the refresh token or the user's API key.
 */

export const UNLOCK_TAB = "vault-unlock";

/** Core turns this code into an unlock prompt on connect (Termix 26.11.3+). */
export class UnlockRequiredError extends Error {
  readonly code = "unlock-required";
  constructor() {
    super(
      "The Bitwarden vault for this login is locked. Unlock it in Secret Sources",
    );
    this.name = "UnlockRequiredError";
  }
}

export type UnlockMethod = "sso" | "password" | "apikey";

export interface StoredSession {
  v: 1;
  method: UnlockMethod;
  email: string;
  userKey: string;
  refreshToken: string | null;
  apiKey: { clientId: string; clientSecret: string } | null;
  expiresAt: number;
}

export type UnlockInput =
  | {
      method: "password";
      email: string;
      password: string;
      twoFactor?: { provider: number; code: string };
    }
  | {
      method: "apikey";
      clientId: string;
      clientSecret: string;
      password: string;
    }
  | { method: "sso"; redirect: string; password: string };

export interface SessionSource {
  id: string;
  baseUrl: string;
  /** The source's stored settings, JSON. */
  credential: string;
}

export interface SessionStatus {
  unlocked: boolean;
  email: string | null;
  method: UnlockMethod | null;
  expiresAt: number | null;
}

const DEFAULT_HOURS = 8;
const MAX_HOURS = 24 * 30;
const SYNC_TTL_MS = 30_000;
const SSO_TTL_MS = 10 * 60_000;

/** How long an unlock lasts for a source, from its settings. */
export function sessionHours(credential: string): number {
  const hours = Number(credentialFields(credential).sessionHours);
  if (!Number.isFinite(hours) || hours <= 0) return DEFAULT_HOURS;
  return Math.min(Math.max(hours, 0.25), MAX_HOURS);
}

export function ssoIdentifier(credential: string): string {
  return credentialFields(credential).ssoIdentifier?.trim() ?? "";
}

function secretKey(sourceId: string): string {
  return `vault:${sourceId}`;
}

function parseSession(raw: string | null): StoredSession | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as StoredSession;
    return parsed?.v === 1 && typeof parsed.userKey === "string"
      ? parsed
      : null;
  } catch {
    return null;
  }
}

export function createVaultSessions(ctx: PluginContext, now = Date.now) {
  const tokens = new Map<string, { token: string; expiresAt: number }>();
  const syncs = new Map<string, { sync: VaultSync; at: number }>();
  const sso = new Map<
    string,
    { state: string; verifier: string; expiresAt: number }
  >();
  const slot = (sourceId: string, userId: string) => `${sourceId}:${userId}`;

  async function read(
    sourceId: string,
    userId: string,
  ): Promise<StoredSession | null> {
    const session = parseSession(
      await ctx.asUser(userId, () => ctx.secrets.get(secretKey(sourceId))),
    );
    if (session && session.expiresAt <= now()) {
      await clear(sourceId, userId);
      return null;
    }
    return session;
  }

  async function users(sourceId: string): Promise<string[]> {
    const list = await ctx.kv.get(`sessions:${sourceId}`);
    return Array.isArray(list) ? list.map(String) : [];
  }

  async function clear(sourceId: string, userId: string): Promise<void> {
    tokens.delete(slot(sourceId, userId));
    syncs.delete(slot(sourceId, userId));
    await ctx.asUser(userId, () => ctx.secrets.delete(secretKey(sourceId)));
    const rest = (await users(sourceId)).filter((id) => id !== userId);
    if (rest.length > 0) await ctx.kv.set(`sessions:${sourceId}`, rest);
    else await ctx.kv.delete(`sessions:${sourceId}`);
  }

  async function deviceId(sourceId: string, userId: string): Promise<string> {
    // One device per user and source, so the server does not see a new
    // device (and mail about it) on every unlock.
    const key = `device:${sourceId}:${userId}`;
    const stored = await ctx.kv.get(key);
    if (typeof stored === "string" && stored) return stored;
    const id = newDeviceId();
    await ctx.kv.set(key, id);
    return id;
  }

  async function accessToken(
    source: SessionSource,
    userId: string,
    session: StoredSession,
    target: VaultTarget,
  ): Promise<string> {
    const cached = tokens.get(slot(source.id, userId));
    if (cached && cached.expiresAt > now() + 60_000) return cached.token;
    let answer: TokenAnswer;
    try {
      if (session.apiKey) {
        answer = await loginWithApiKey(
          ctx.fetch,
          target,
          await deviceId(source.id, userId),
          session.apiKey.clientId,
          session.apiKey.clientSecret,
        );
      } else if (session.refreshToken) {
        answer = await refreshAccessToken(
          ctx.fetch,
          target,
          session.refreshToken,
        );
      } else {
        throw new VaultLoginError("Session expired");
      }
    } catch (error) {
      if (error instanceof VaultLoginError) {
        // The server ended the session: sign in again.
        await clear(source.id, userId);
        throw new UnlockRequiredError();
      }
      throw error;
    }
    if (answer.refreshToken && answer.refreshToken !== session.refreshToken) {
      await write(source.id, userId, {
        ...session,
        refreshToken: answer.refreshToken,
      });
    }
    tokens.set(slot(source.id, userId), {
      token: answer.accessToken,
      expiresAt: now() + answer.expiresIn * 1000,
    });
    return answer.accessToken;
  }

  async function write(
    sourceId: string,
    userId: string,
    session: StoredSession,
  ): Promise<void> {
    await ctx.asUser(userId, () =>
      ctx.secrets.set(secretKey(sourceId), JSON.stringify(session)),
    );
    const list = await users(sourceId);
    if (!list.includes(userId)) {
      await ctx.kv.set(`sessions:${sourceId}`, [...list, userId]);
    }
  }

  return {
    clear,

    /** Locks a source for everyone, when it is deleted or moved. */
    async clearAll(sourceId: string): Promise<void> {
      for (const userId of await users(sourceId)) {
        await clear(sourceId, userId);
      }
    },

    async status(sourceId: string, userId: string): Promise<SessionStatus> {
      const session = await read(sourceId, userId);
      return {
        unlocked: !!session,
        email: session?.email ?? null,
        method: session?.method ?? null,
        expiresAt: session?.expiresAt ?? null,
      };
    },

    /** The user's vault, synced at most every 30 seconds. */
    async open(
      source: SessionSource,
      userId: string,
      target: VaultTarget,
    ): Promise<OpenVault> {
      const session = await read(source.id, userId);
      if (!session) throw new UnlockRequiredError();
      const userKey = Buffer.from(session.userKey, "base64");
      const cached = syncs.get(slot(source.id, userId));
      if (cached && cached.at + SYNC_TTL_MS > now()) {
        return { sync: cached.sync, userKey };
      }
      const token = await accessToken(source, userId, session, target);
      let sync: VaultSync;
      try {
        sync = await fetchSync(ctx.fetch, target, token);
      } catch (error) {
        if (!(error instanceof VaultLoginError)) throw error;
        tokens.delete(slot(source.id, userId));
        sync = await fetchSync(
          ctx.fetch,
          target,
          await accessToken(source, userId, session, target),
        );
      }
      syncs.set(slot(source.id, userId), { sync, at: now() });
      return { sync, userKey };
    },

    /** The address to start an SSO sign in at. */
    startSso(source: SessionSource, userId: string): string {
      const start = startSso(source.baseUrl, ssoIdentifier(source.credential));
      sso.set(slot(source.id, userId), {
        state: start.state,
        verifier: start.verifier,
        expiresAt: now() + SSO_TTL_MS,
      });
      return start.url;
    },

    async unlock(
      source: SessionSource,
      userId: string,
      target: VaultTarget,
      input: UnlockInput,
    ): Promise<SessionStatus> {
      const device = await deviceId(source.id, userId);
      let answer: TokenAnswer;
      let masterKey: Buffer | undefined;
      if (input.method === "password") {
        ({ answer, masterKey } = await loginWithPassword(
          ctx.fetch,
          target,
          device,
          input.email.trim(),
          input.password,
          input.twoFactor,
        ));
      } else if (input.method === "apikey") {
        answer = await loginWithApiKey(
          ctx.fetch,
          target,
          device,
          input.clientId.trim(),
          input.clientSecret.trim(),
        );
      } else {
        const pending = sso.get(slot(source.id, userId));
        if (!pending || pending.expiresAt <= now()) {
          throw new VaultLoginError("Start the SSO sign in again");
        }
        const code = ssoCodeFrom(input.redirect, pending.state);
        sso.delete(slot(source.id, userId));
        answer = await loginWithSsoCode(
          ctx.fetch,
          target,
          device,
          code,
          pending.verifier,
        );
      }
      const { userKey, email } = await unlockUserKey(
        answer,
        input.password,
        masterKey,
      );
      const session: StoredSession = {
        v: 1,
        method: input.method,
        email,
        userKey: userKey.toString("base64"),
        refreshToken: answer.refreshToken,
        apiKey:
          input.method === "apikey"
            ? {
                clientId: input.clientId.trim(),
                clientSecret: input.clientSecret.trim(),
              }
            : null,
        expiresAt: now() + sessionHours(source.credential) * 3_600_000,
      };
      await write(source.id, userId, session);
      syncs.delete(slot(source.id, userId));
      tokens.set(slot(source.id, userId), {
        token: answer.accessToken,
        expiresAt: now() + answer.expiresIn * 1000,
      });
      return {
        unlocked: true,
        email,
        method: input.method,
        expiresAt: session.expiresAt,
      };
    },
  };
}

export type VaultSessions = ReturnType<typeof createVaultSessions>;
