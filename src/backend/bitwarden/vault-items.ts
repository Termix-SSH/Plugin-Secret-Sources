import type { SymmetricKey } from "../providers/bitwarden-sm.js";
import { decryptEncString } from "../providers/bitwarden-sm.js";
import { PICK_LIMIT, type PickItem } from "../providers/types.js";
import type { VaultCipher, VaultSync } from "./vault-client.js";
import {
  decryptPrivateKey,
  decryptRsa,
  decryptText,
  symmetricKey,
  totpCode,
} from "./vault-crypto.js";

/** A synced vault and the key that opens it. */
export interface OpenVault {
  sync: VaultSync;
  userKey: Buffer;
}

export interface DecryptedItem {
  cipher: VaultCipher;
  key: SymmetricKey;
  name: string;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Every item the account can read, each with the key for its fields. */
export function decryptItems(vault: OpenVault): DecryptedItem[] {
  const userKey = symmetricKey(vault.userKey);
  const orgKeys = new Map<string, SymmetricKey>();
  const organizations = vault.sync.profile?.organizations ?? [];
  if (organizations.length > 0 && vault.sync.profile?.privateKey) {
    const privateKey = decryptPrivateKey(
      vault.sync.profile.privateKey,
      userKey,
    );
    for (const org of organizations) {
      if (!org.id || !org.key) continue;
      try {
        orgKeys.set(org.id, symmetricKey(decryptRsa(org.key, privateKey)));
      } catch {
        // An organization key that does not open leaves its items out.
      }
    }
  }
  const items: DecryptedItem[] = [];
  for (const cipher of vault.sync.ciphers ?? []) {
    if (cipher.deletedDate) continue;
    const parent = cipher.organizationId
      ? orgKeys.get(cipher.organizationId)
      : userKey;
    if (!parent) continue;
    try {
      const key = cipher.key
        ? symmetricKey(decryptEncString(cipher.key, parent))
        : parent;
      items.push({ cipher, key, name: decryptText(cipher.name, key) ?? "" });
    } catch {
      // An item that does not decrypt is skipped, like the official clients.
    }
  }
  return items;
}

export function findItem(items: DecryptedItem[], item: string): DecryptedItem {
  if (UUID.test(item)) {
    const byId = items.find(
      (entry) => entry.cipher.id.toLowerCase() === item.toLowerCase(),
    );
    if (byId) return byId;
  }
  const matches = items.filter(
    (entry) => entry.name.toLowerCase() === item.toLowerCase(),
  );
  if (matches.length === 0) {
    throw new Error(`Bitwarden item "${item}" not found`);
  }
  if (matches.length > 1) {
    throw new Error(`More than one Bitwarden item is named "${item}"`);
  }
  return matches[0];
}

/** username, password, totp, notes, uri, privatekey, publickey or a custom field. */
export function readField(
  entry: DecryptedItem,
  field: string,
  now = Date.now(),
): string {
  const { cipher, key } = entry;
  const name = field.toLowerCase();
  let value: string | null = null;
  if (name === "username") value = decryptText(cipher.login?.username, key);
  else if (name === "password") {
    value = decryptText(cipher.login?.password, key);
  } else if (name === "notes") value = decryptText(cipher.notes, key);
  else if (name === "uri") {
    value = decryptText(cipher.login?.uris?.[0]?.uri, key);
  } else if (name === "totp") {
    const secret = decryptText(cipher.login?.totp, key);
    value = secret ? totpCode(secret, now) : null;
  } else if (name === "privatekey") {
    value = decryptText(cipher.sshKey?.privateKey, key);
  } else if (name === "publickey") {
    value = decryptText(cipher.sshKey?.publicKey, key);
  } else {
    for (const custom of cipher.fields ?? []) {
      if ((decryptText(custom.name, key) ?? "").toLowerCase() === name) {
        value = decryptText(custom.value, key);
        break;
      }
    }
  }
  if (value === null) {
    throw new Error(`Bitwarden field "${field}" not found on "${entry.name}"`);
  }
  return value;
}

/** Logins as picker items, by id. */
export function vaultPickItems(
  vault: OpenVault,
  items: DecryptedItem[],
  search: string,
): PickItem[] {
  const userKey = symmetricKey(vault.userKey);
  const folders = new Map<string, string>();
  for (const folder of vault.sync.folders ?? []) {
    if (!folder.id) continue;
    try {
      folders.set(folder.id, decryptText(folder.name, userKey) ?? "");
    } catch {
      // Unnamed folder.
    }
  }
  const query = search.trim().toLowerCase();
  return items
    .filter((entry) => entry.cipher.login)
    .filter((entry) => !query || entry.name.toLowerCase().includes(query))
    .slice(0, PICK_LIMIT)
    .map(({ cipher, name }) => ({
      id: cipher.id,
      name,
      folder: cipher.folderId ? (folders.get(cipher.folderId) ?? null) : null,
      username: cipher.login?.username ? `bw://${cipher.id}/username` : null,
      password: cipher.login?.password ? `bw://${cipher.id}/password` : null,
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
}
