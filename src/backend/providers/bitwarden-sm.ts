import {
  createDecipheriv,
  createHmac,
  hkdfSync,
  timingSafeEqual,
} from "node:crypto";
import type { PluginFetch } from "@termix-ssh/plugin-sdk/backend";
import {
  referenceParts,
  requestJson,
  trimBase,
  type ProviderSource,
  type SecretProvider,
} from "./types.js";

/**
 * Bitwarden Secrets Manager with a machine account access token. Secrets are
 * end to end encrypted, so the token's key unlocks the organization key here.
 * bws://<secret id>
 */
export interface BitwardenSmReference {
  secretId: string;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function parseBitwardenSmReference(
  raw: string,
): BitwardenSmReference | null {
  const parts = referenceParts(raw, "bws");
  if (!parts || parts.length !== 1 || !UUID.test(parts[0])) return null;
  return { secretId: parts[0] };
}

export interface AccessToken {
  id: string;
  clientSecret: string;
  /** 16 bytes. */
  encryptionKey: Buffer;
}

/** "0.<id>.<client secret>:<base64 key>" */
export function parseAccessToken(raw: string): AccessToken | null {
  const match = /^0\.([0-9a-f-]{36})\.([^:]+):([A-Za-z0-9+/=]+)$/i.exec(
    raw.trim(),
  );
  if (!match) return null;
  const encryptionKey = Buffer.from(match[3], "base64");
  if (encryptionKey.length !== 16) return null;
  return { id: match[1], clientSecret: match[2], encryptionKey };
}

export interface SymmetricKey {
  enc: Buffer;
  mac: Buffer;
}

/**
 * Bitwarden's shareable key derivation. Its PRK is HMAC keyed with
 * "bitwarden-<name>" over the secret, which is HKDF extract with that salt.
 */
export function deriveShareableKey(
  secret: Buffer,
  name: string,
  info: string,
): SymmetricKey {
  const okm = Buffer.from(
    hkdfSync("sha256", secret, `bitwarden-${name}`, info, 64),
  );
  return { enc: okm.subarray(0, 32), mac: okm.subarray(32, 64) };
}

/** Decrypts a type 2 EncString: "2.<iv>|<data>|<mac>", AES-256-CBC with HMAC-SHA256. */
export function decryptEncString(value: string, key: SymmetricKey): Buffer {
  const match = /^2\.([^|]+)\|([^|]+)\|([^|]+)$/.exec(value.trim());
  if (!match) throw new Error("Unsupported Bitwarden encryption type");
  const iv = Buffer.from(match[1], "base64");
  const data = Buffer.from(match[2], "base64");
  const mac = Buffer.from(match[3], "base64");
  const expected = createHmac("sha256", key.mac)
    .update(Buffer.concat([iv, data]))
    .digest();
  if (expected.length !== mac.length || !timingSafeEqual(expected, mac)) {
    throw new Error("Bitwarden secret failed its integrity check");
  }
  const decipher = createDecipheriv("aes-256-cbc", key.enc, iv);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

/** The identity and API servers for a Bitwarden server address. */
export function bitwardenEndpoints(baseUrl: string): {
  identity: string;
  api: string;
} {
  const base = trimBase(baseUrl || "https://vault.bitwarden.com");
  const host = (() => {
    try {
      return new URL(base).hostname.toLowerCase();
    } catch {
      return "";
    }
  })();
  for (const cloud of ["bitwarden.com", "bitwarden.eu"]) {
    if (host === cloud || host === `vault.${cloud}`) {
      return {
        identity: `https://identity.${cloud}`,
        api: `https://api.${cloud}`,
      };
    }
  }
  return { identity: `${base}/identity`, api: `${base}/api` };
}

interface Session {
  accessToken: string;
  orgKey: SymmetricKey;
}

async function login(
  fetch: PluginFetch,
  source: ProviderSource,
): Promise<Session> {
  const token = parseAccessToken(source.credential);
  if (!token) throw new Error("That is not a Bitwarden access token");
  const { identity } = bitwardenEndpoints(source.baseUrl);
  const result = await requestJson<{
    access_token?: string;
    encrypted_payload?: string;
  }>(fetch, source, `${identity}/connect/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      scope: "api.secrets",
      grant_type: "client_credentials",
      client_id: token.id,
      client_secret: token.clientSecret,
    }).toString(),
    label: "Bitwarden login",
  });
  if (!result.access_token || !result.encrypted_payload) {
    throw new Error("Bitwarden login gave no token");
  }
  const tokenKey = deriveShareableKey(
    token.encryptionKey,
    "accesstoken",
    "sm-access-token",
  );
  const payload = JSON.parse(
    decryptEncString(result.encrypted_payload, tokenKey).toString("utf8"),
  ) as { encryptionKey?: string };
  const orgKey = Buffer.from(payload.encryptionKey ?? "", "base64");
  if (orgKey.length !== 64) throw new Error("Bitwarden gave an unusable key");
  return {
    accessToken: result.access_token,
    orgKey: { enc: orgKey.subarray(0, 32), mac: orgKey.subarray(32, 64) },
  };
}

export const bitwardenSmProvider: SecretProvider<BitwardenSmReference> = {
  kind: "bitwarden-sm",
  scheme: "bws",
  needsCredential: true,
  parseReference: parseBitwardenSmReference,
  async resolve(fetch, source, ref) {
    const session = await login(fetch, source);
    const { api } = bitwardenEndpoints(source.baseUrl);
    const secret = await requestJson<{ value?: string }>(
      fetch,
      source,
      `${api}/secrets/${encodeURIComponent(ref.secretId)}`,
      {
        headers: { Authorization: `Bearer ${session.accessToken}` },
        label: `Bitwarden secret ${ref.secretId}`,
      },
    );
    if (!secret.value) {
      throw new Error(`Bitwarden secret ${ref.secretId} has no value`);
    }
    return decryptEncString(secret.value, session.orgKey).toString("utf8");
  },
  async test(fetch, source) {
    await login(fetch, source);
    return "Signed in";
  },
};
