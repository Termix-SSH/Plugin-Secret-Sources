import {
  createHash,
  createHmac,
  createPrivateKey,
  pbkdf2Sync,
  privateDecrypt,
  constants,
  type KeyObject,
} from "node:crypto";
import { argon2id } from "hash-wasm";
import {
  decryptEncString,
  type SymmetricKey,
} from "../providers/bitwarden-sm.js";

/**
 * The client side of a Bitwarden or Vaultwarden account: the master key from
 * the master password, the user key it unwraps, and the item fields the user
 * key (or an organization key) decrypts. Same math as the official clients.
 */

export interface KdfParams {
  /** 0 PBKDF2-SHA256, 1 Argon2id. */
  kdf: number;
  iterations: number;
  /** MiB, Argon2id only. */
  memory?: number | null;
  parallelism?: number | null;
}

// The official clients' floors. A server asking for less could be trying to
// make the password hash it receives cheap to crack.
const PBKDF2_MIN = 5000;
const ARGON2_MIN = { iterations: 2, memory: 16, parallelism: 1 };

export function checkKdf(params: KdfParams): void {
  if (params.kdf === 0) {
    if (!(params.iterations >= PBKDF2_MIN)) {
      throw new Error("The server asked for too few PBKDF2 iterations");
    }
    return;
  }
  if (params.kdf === 1) {
    if (
      !(params.iterations >= ARGON2_MIN.iterations) ||
      !((params.memory ?? 0) >= ARGON2_MIN.memory) ||
      !((params.parallelism ?? 0) >= ARGON2_MIN.parallelism)
    ) {
      throw new Error("The server asked for Argon2 settings that are too weak");
    }
    return;
  }
  throw new Error("Unsupported Bitwarden key derivation");
}

export async function makeMasterKey(
  password: string,
  salt: string,
  params: KdfParams,
): Promise<Buffer> {
  checkKdf(params);
  const normalized = salt.trim().toLowerCase();
  if (params.kdf === 0) {
    return pbkdf2Sync(password, normalized, params.iterations, 32, "sha256");
  }
  const out = await argon2id({
    password,
    salt: new Uint8Array(createHash("sha256").update(normalized).digest()),
    iterations: params.iterations,
    memorySize: (params.memory as number) * 1024,
    parallelism: params.parallelism as number,
    hashLength: 32,
    outputType: "binary",
  });
  return Buffer.from(out);
}

/** What the server checks a password login against. */
export function masterPasswordHash(
  masterKey: Buffer,
  password: string,
): string {
  return pbkdf2Sync(masterKey, password, 1, 32, "sha256").toString("base64");
}

/** HKDF-Expand only, which is all the stretch step uses. */
function hkdfExpand(prk: Buffer, info: string): Buffer {
  return createHmac("sha256", prk)
    .update(Buffer.concat([Buffer.from(info), Buffer.from([1])]))
    .digest();
}

export function stretchMasterKey(masterKey: Buffer): SymmetricKey {
  return {
    enc: hkdfExpand(masterKey, "enc"),
    mac: hkdfExpand(masterKey, "mac"),
  };
}

export function symmetricKey(raw: Buffer): SymmetricKey {
  if (raw.length !== 64) throw new Error("Bitwarden gave an unusable key");
  return { enc: raw.subarray(0, 32), mac: raw.subarray(32, 64) };
}

/** The user key, or a "wrong master password" error when it does not open. */
export function unwrapUserKey(
  encryptedUserKey: string,
  masterKey: Buffer,
): Buffer {
  let raw: Buffer;
  try {
    raw = decryptEncString(encryptedUserKey, stretchMasterKey(masterKey));
  } catch (error) {
    if (/integrity/i.test((error as Error).message)) {
      throw new Error("Wrong master password");
    }
    throw error;
  }
  symmetricKey(raw);
  return raw;
}

export function decryptPrivateKey(
  encrypted: string,
  userKey: SymmetricKey,
): KeyObject {
  return createPrivateKey({
    key: decryptEncString(encrypted, userKey),
    format: "der",
    type: "pkcs8",
  });
}

/** Type 3 (OAEP SHA-256) and 4 (OAEP SHA-1) RSA EncStrings. */
export function decryptRsa(value: string, privateKey: KeyObject): Buffer {
  const match = /^([34])\.([A-Za-z0-9+/=]+)$/.exec(value.trim());
  if (!match) throw new Error("Unsupported Bitwarden organization key");
  return privateDecrypt(
    {
      key: privateKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: match[1] === "3" ? "sha256" : "sha1",
    },
    Buffer.from(match[2], "base64"),
  );
}

export function decryptText(
  value: string | null | undefined,
  key: SymmetricKey,
): string | null {
  if (!value) return null;
  return decryptEncString(value, key).toString("utf8");
}

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Decode(input: string): Buffer {
  const clean = input.toUpperCase().replace(/[\s=-]/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const char of clean) {
    const index = BASE32.indexOf(char);
    if (index < 0) throw new Error("The TOTP secret is not base32");
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** The current code for a stored TOTP secret or otpauth:// address. */
export function totpCode(stored: string, now = Date.now()): string {
  let secret = stored.trim();
  let digits = 6;
  let period = 30;
  let algorithm = "sha1";
  if (/^otpauth:\/\//i.test(secret)) {
    const url = new URL(secret);
    secret = url.searchParams.get("secret") ?? "";
    digits = Number(url.searchParams.get("digits")) || digits;
    period = Number(url.searchParams.get("period")) || period;
    const algo = (url.searchParams.get("algorithm") ?? "").toLowerCase();
    if (algo === "sha256" || algo === "sha512") algorithm = algo;
  } else if (/^steam:\/\//i.test(secret)) {
    throw new Error("Steam TOTP codes are not supported");
  }
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(now / 1000 / period)));
  const hmac = createHmac(algorithm, base32Decode(secret))
    .update(counter)
    .digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const code = (hmac.readUInt32BE(offset) & 0x7fffffff) % 10 ** digits;
  return String(code).padStart(digits, "0");
}
