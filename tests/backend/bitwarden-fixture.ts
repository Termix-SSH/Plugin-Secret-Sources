import {
  createCipheriv,
  createHmac,
  generateKeyPairSync,
  publicEncrypt,
  constants,
  randomBytes,
} from "node:crypto";
import {
  makeMasterKey,
  masterPasswordHash,
  stretchMasterKey,
  type KdfParams,
} from "../../src/backend/bitwarden/vault-crypto.js";
import type { SymmetricKey } from "../../src/backend/providers/bitwarden-sm.js";

/** Bitwarden encryption the way the official clients write it, for tests. */

export function key64(raw: Buffer): SymmetricKey {
  return { enc: raw.subarray(0, 32), mac: raw.subarray(32, 64) };
}

export function enc(data: string | Buffer, key: SymmetricKey): string {
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-256-cbc", key.enc, iv);
  const body = Buffer.concat([cipher.update(data), cipher.final()]);
  const mac = createHmac("sha256", key.mac)
    .update(Buffer.concat([iv, body]))
    .digest();
  return `2.${iv.toString("base64")}|${body.toString("base64")}|${mac.toString("base64")}`;
}

export interface TestAccount {
  email: string;
  password: string;
  kdf: KdfParams;
  userKey: Buffer;
  encryptedUserKey: string;
  passwordHash: string;
  publicKey: string;
  encryptedPrivateKey: string;
}

export async function makeAccount(
  email: string,
  password: string,
  kdf: KdfParams = { kdf: 0, iterations: 5000 },
): Promise<TestAccount> {
  const masterKey = await makeMasterKey(password, email, kdf);
  const userKey = randomBytes(64);
  const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return {
    email,
    password,
    kdf,
    userKey,
    encryptedUserKey: enc(userKey, stretchMasterKey(masterKey)),
    passwordHash: masterPasswordHash(masterKey, password),
    publicKey: pair.publicKey
      .export({ type: "spki", format: "der" })
      .toString("base64"),
    encryptedPrivateKey: enc(
      pair.privateKey.export({ type: "pkcs8", format: "der" }),
      key64(userKey),
    ),
  };
}

/** An organization key wrapped for a member, as type 4 RSA. */
export function wrapOrgKey(orgKey: Buffer, publicKeyB64: string): string {
  const wrapped = publicEncrypt(
    {
      key: Buffer.from(publicKeyB64, "base64"),
      format: "der",
      type: "spki",
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha1",
    },
    orgKey,
  );
  return `4.${wrapped.toString("base64")}`;
}

export function loginCipher(
  key: SymmetricKey,
  fields: {
    name: string;
    username?: string;
    password?: string;
    totp?: string;
    custom?: Record<string, string>;
  },
): Record<string, unknown> {
  return {
    type: 1,
    name: enc(fields.name, key),
    notes: null,
    favorite: false,
    reprompt: 0,
    login: {
      username: fields.username ? enc(fields.username, key) : null,
      password: fields.password ? enc(fields.password, key) : null,
      totp: fields.totp ? enc(fields.totp, key) : null,
      uris: [],
    },
    fields: Object.entries(fields.custom ?? {}).map(([name, value]) => ({
      type: 1,
      name: enc(name, key),
      value: enc(value, key),
    })),
  };
}
