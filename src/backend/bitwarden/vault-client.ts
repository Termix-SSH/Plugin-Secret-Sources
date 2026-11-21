import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { PluginFetch } from "@termix-ssh/plugin-sdk/backend";
import { bitwardenEndpoints } from "../providers/bitwarden-sm.js";
import { FETCH_TIMEOUT_MS, trimBase } from "../providers/types.js";
import {
  makeMasterKey,
  masterPasswordHash,
  unwrapUserKey,
  type KdfParams,
} from "./vault-crypto.js";

/**
 * Talks to a Bitwarden or Vaultwarden server as a client of its own, the way
 * the CLI does, so each Termix user signs in with their own account. Logins
 * use the CLI's client id, which is also the one Vaultwarden lets finish an
 * SSO login on a localhost address.
 */

const CLIENT_ID = "cli";
const DEVICE_TYPE = "23";
const CLIENT_VERSION = "2025.10.0";
export const SSO_REDIRECT = "http://localhost:8065";

export interface VaultTarget {
  baseUrl: string;
  allowedPrivateHosts: readonly string[];
}

export interface TokenAnswer {
  accessToken: string;
  expiresIn: number;
  refreshToken: string | null;
  /** The encrypted user key and how to derive the key that opens it. */
  key: string | null;
  kdf: KdfParams | null;
  salt: string | null;
}

export class VaultLoginError extends Error {
  constructor(
    message: string,
    readonly twoFactor: number[] | null = null,
  ) {
    super(message);
    this.name = "VaultLoginError";
  }
}

/** Server JSON comes in either case; this reads it in camelCase. */
export function camel(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(camel);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value).map(([key, inner]) => [
      key.charAt(0).toLowerCase() + key.slice(1),
      camel(inner),
    ]),
  );
}

function clientHeaders(): Record<string, string> {
  return {
    "Bitwarden-Client-Name": CLIENT_ID,
    "Bitwarden-Client-Version": CLIENT_VERSION,
    "Device-Type": DEVICE_TYPE,
  };
}

async function readJson(response: Response): Promise<Record<string, unknown>> {
  try {
    return camel(await response.json()) as Record<string, unknown>;
  } catch {
    return {};
  }
}

function jwtEmail(token: string): string | null {
  try {
    const payload = JSON.parse(
      Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8"),
    ) as { email?: unknown };
    return typeof payload.email === "string" ? payload.email : null;
  } catch {
    return null;
  }
}

function num(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function str(value: unknown): string | null {
  return typeof value === "string" && value ? value : null;
}

export function parseTokenAnswer(body: Record<string, unknown>): TokenAnswer {
  const accessToken = str(body.access_token);
  if (!accessToken) throw new VaultLoginError("The server gave no token");
  const unlock = (
    body.userDecryptionOptions as
      { masterPasswordUnlock?: Record<string, unknown> } | undefined
  )?.masterPasswordUnlock;
  const unlockKdf = unlock?.kdf as Record<string, unknown> | undefined;
  let kdf: KdfParams | null = null;
  if (unlockKdf && num(unlockKdf.kdfType) !== null) {
    kdf = {
      kdf: num(unlockKdf.kdfType) as number,
      iterations: num(unlockKdf.iterations) ?? 0,
      memory: num(unlockKdf.memory),
      parallelism: num(unlockKdf.parallelism),
    };
  } else if (num(body.kdf) !== null) {
    kdf = {
      kdf: num(body.kdf) as number,
      iterations: num(body.kdfIterations) ?? 0,
      memory: num(body.kdfMemory),
      parallelism: num(body.kdfParallelism),
    };
  }
  return {
    accessToken,
    expiresIn: num(body.expires_in) ?? 3600,
    refreshToken: str(body.refresh_token),
    key:
      str(unlock?.masterKeyWrappedUserKey) ??
      str(unlock?.masterKeyEncryptedUserKey) ??
      str(body.key),
    kdf,
    salt: str(unlock?.salt) ?? jwtEmail(accessToken),
  };
}

async function token(
  fetch: PluginFetch,
  target: VaultTarget,
  form: Record<string, string>,
): Promise<TokenAnswer> {
  const { identity } = bitwardenEndpoints(target.baseUrl);
  const response = await fetch(`${identity}/connect/token`, {
    method: "POST",
    headers: {
      ...clientHeaders(),
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(form).toString(),
    timeoutMs: FETCH_TIMEOUT_MS,
    allowPrivateHosts: target.allowedPrivateHosts,
  });
  const body = await readJson(response);
  if (!response.ok) {
    const providers = body.twoFactorProviders;
    if (Array.isArray(providers) && providers.length > 0) {
      throw new VaultLoginError(
        "Two-step login is required",
        providers.map(Number).filter((n) => Number.isInteger(n)),
      );
    }
    const detail =
      str((body.errorModel as { message?: unknown } | undefined)?.message) ??
      str(body.error_description) ??
      str(body.message) ??
      `HTTP ${response.status}`;
    throw new VaultLoginError(`Sign in failed: ${detail}`);
  }
  return parseTokenAnswer(body);
}

function device(deviceId: string): Record<string, string> {
  return {
    deviceType: DEVICE_TYPE,
    deviceIdentifier: deviceId,
    deviceName: "Termix",
  };
}

export async function prelogin(
  fetch: PluginFetch,
  target: VaultTarget,
  email: string,
): Promise<KdfParams> {
  const { identity } = bitwardenEndpoints(target.baseUrl);
  const response = await fetch(`${identity}/accounts/prelogin`, {
    method: "POST",
    headers: { ...clientHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
    timeoutMs: FETCH_TIMEOUT_MS,
    allowPrivateHosts: target.allowedPrivateHosts,
  });
  if (!response.ok) {
    throw new VaultLoginError(`Sign in failed: HTTP ${response.status}`);
  }
  const body = await readJson(response);
  return {
    kdf: num(body.kdf) ?? 0,
    iterations: num(body.kdfIterations) ?? 0,
    memory: num(body.kdfMemory),
    parallelism: num(body.kdfParallelism),
  };
}

export function loginWithApiKey(
  fetch: PluginFetch,
  target: VaultTarget,
  deviceId: string,
  clientId: string,
  clientSecret: string,
): Promise<TokenAnswer> {
  return token(fetch, target, {
    grant_type: "client_credentials",
    scope: "api",
    client_id: clientId,
    client_secret: clientSecret,
    ...device(deviceId),
  });
}

export async function loginWithPassword(
  fetch: PluginFetch,
  target: VaultTarget,
  deviceId: string,
  email: string,
  password: string,
  twoFactor?: { provider: number; code: string },
): Promise<{ answer: TokenAnswer; masterKey: Buffer }> {
  const kdf = await prelogin(fetch, target, email);
  const masterKey = await makeMasterKey(password, email, kdf);
  const answer = await token(fetch, target, {
    grant_type: "password",
    scope: "api offline_access",
    client_id: CLIENT_ID,
    username: email,
    password: masterPasswordHash(masterKey, password),
    ...device(deviceId),
    ...(twoFactor
      ? {
          twoFactorProvider: String(twoFactor.provider),
          twoFactorToken: twoFactor.code,
          twoFactorRemember: "0",
        }
      : {}),
  });
  return { answer, masterKey };
}

export interface SsoStart {
  url: string;
  state: string;
  verifier: string;
}

/**
 * The address that starts an SSO login in the person's own browser. It ends
 * on SSO_REDIRECT with the code, which they paste back.
 */
export function startSso(baseUrl: string, identifier = ""): SsoStart {
  const { identity } = bitwardenEndpoints(baseUrl);
  const verifier = randomBytes(32).toString("base64url");
  const state = randomBytes(24).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: SSO_REDIRECT,
    response_type: "code",
    scope: "api offline_access",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
    domain_hint: identifier,
    ssoToken: "",
  });
  return { url: `${identity}/connect/authorize?${params}`, state, verifier };
}

/** The code from the address the SSO window ended on, checked against state. */
export function ssoCodeFrom(pasted: string, state: string): string {
  let url: URL;
  try {
    url = new URL(pasted.trim());
  } catch {
    throw new VaultLoginError("Paste the full address the window ended on");
  }
  if (url.searchParams.get("state") !== state) {
    throw new VaultLoginError("That address is from a different sign in");
  }
  const code = url.searchParams.get("code");
  if (!code) throw new VaultLoginError("That address has no sign in code");
  return code;
}

export function loginWithSsoCode(
  fetch: PluginFetch,
  target: VaultTarget,
  deviceId: string,
  code: string,
  verifier: string,
): Promise<TokenAnswer> {
  return token(fetch, target, {
    grant_type: "authorization_code",
    scope: "api offline_access",
    client_id: CLIENT_ID,
    code,
    code_verifier: verifier,
    redirect_uri: SSO_REDIRECT,
    ...device(deviceId),
  });
}

export function refreshAccessToken(
  fetch: PluginFetch,
  target: VaultTarget,
  refreshToken: string,
): Promise<TokenAnswer> {
  return token(fetch, target, {
    grant_type: "refresh_token",
    client_id: CLIENT_ID,
    refresh_token: refreshToken,
  });
}

/** Opens the user key with the master password, given a token answer. */
export async function unlockUserKey(
  answer: TokenAnswer,
  password: string,
  masterKey?: Buffer,
): Promise<{ userKey: Buffer; email: string }> {
  if (!answer.key || !answer.kdf || !answer.salt) {
    throw new VaultLoginError(
      "This account has no master password to unlock with",
    );
  }
  const key =
    masterKey ?? (await makeMasterKey(password, answer.salt, answer.kdf));
  return { userKey: unwrapUserKey(answer.key, key), email: answer.salt };
}

export async function fetchSync(
  fetch: PluginFetch,
  target: VaultTarget,
  accessToken: string,
): Promise<VaultSync> {
  const { api } = bitwardenEndpoints(target.baseUrl);
  const response = await fetch(`${api}/sync?excludeDomains=true`, {
    headers: { ...clientHeaders(), Authorization: `Bearer ${accessToken}` },
    timeoutMs: FETCH_TIMEOUT_MS,
    allowPrivateHosts: target.allowedPrivateHosts,
  });
  if (response.status === 401) throw new VaultLoginError("Session expired");
  if (!response.ok) {
    throw new Error(`Bitwarden sync failed: HTTP ${response.status}`);
  }
  return (await readJson(response)) as unknown as VaultSync;
}

export interface VaultCipher {
  id: string;
  type: number;
  organizationId?: string | null;
  folderId?: string | null;
  deletedDate?: string | null;
  key?: string | null;
  name?: string | null;
  notes?: string | null;
  login?: {
    username?: string | null;
    password?: string | null;
    totp?: string | null;
    uris?: Array<{ uri?: string | null }> | null;
  } | null;
  sshKey?: {
    privateKey?: string | null;
    publicKey?: string | null;
  } | null;
  fields?: Array<{ name?: string | null; value?: string | null }> | null;
}

export interface VaultSync {
  profile?: {
    privateKey?: string | null;
    organizations?: Array<{ id?: string; key?: string | null }> | null;
  };
  folders?: Array<{ id?: string; name?: string | null }> | null;
  ciphers?: VaultCipher[] | null;
}

export function newDeviceId(): string {
  return randomUUID();
}

export function sameServer(a: string, b: string): boolean {
  return trimBase(a).toLowerCase() === trimBase(b).toLowerCase();
}
