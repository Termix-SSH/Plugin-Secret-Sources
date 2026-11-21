import crypto from "node:crypto";
import * as kdbxweb from "kdbxweb";
import { argon2d, argon2id } from "hash-wasm";
import {
  FETCH_TIMEOUT_MS,
  PICK_LIMIT,
  credentialFields,
  type PickItem,
  type ProviderSource,
  type SecretProvider,
} from "./types.js";

/**
 * A KeePass database (.kdbx, version 3 or 4) served over HTTP(S), like a
 * WebDAV share or Nextcloud. The source URL is the file's address.
 * kdbx://<group>/<sub group>/<entry title>[#field]
 */
export interface KeepassReference {
  groups: string[];
  title: string;
  /** Password when left out. */
  field: string;
}

const MAX_BYTES = 10 * 1024 * 1024;
const CACHE_MS = 5 * 60_000;

kdbxweb.CryptoEngine.setArgon2Impl(
  async (password, salt, memory, iterations, length, parallelism, type) => {
    const hash =
      type === kdbxweb.CryptoEngine.Argon2TypeArgon2id ? argon2id : argon2d;
    const out = await hash({
      password: new Uint8Array(password),
      salt: new Uint8Array(salt),
      memorySize: memory,
      iterations,
      hashLength: length,
      parallelism,
      outputType: "binary",
    });
    return out.buffer.slice(
      out.byteOffset,
      out.byteOffset + out.byteLength,
    ) as ArrayBuffer;
  },
);

export function parseKeepassReference(raw: string): KeepassReference | null {
  const value = raw.trim();
  if (!value.toLowerCase().startsWith("kdbx://")) return null;
  const rest = value.slice("kdbx://".length);
  const hash = rest.lastIndexOf("#");
  const path = hash === -1 ? rest : rest.slice(0, hash);
  try {
    const parts = path.split("/").map((part) => decodeURIComponent(part));
    if (parts.some((part) => !part)) return null;
    const title = parts.pop();
    if (!title) return null;
    const field =
      hash === -1 ? "Password" : decodeURIComponent(rest.slice(hash + 1));
    return { groups: parts, title, field: field || "Password" };
  } catch {
    return null;
  }
}

/** The KeePass field a reference names, with easy lowercase names. */
function fieldName(field: string): string {
  const known: Record<string, string> = {
    password: "Password",
    username: "UserName",
    user: "UserName",
    url: "URL",
    notes: "Notes",
    title: "Title",
  };
  return known[field.toLowerCase()] ?? field;
}

const opened = new Map<string, { db: kdbxweb.Kdbx; at: number }>();

type Fetch = Parameters<SecretProvider["resolve"]>[0];

async function open(
  fetch: Fetch,
  source: ProviderSource,
): Promise<kdbxweb.Kdbx> {
  const fields = credentialFields(source.credential);
  if (!fields.masterPassword && !fields.keyFile) {
    throw new Error("KeePass needs the master password or a key file");
  }
  const key = crypto
    .createHash("sha256")
    .update(`${source.baseUrl}\n${source.credential}`)
    .digest("hex");
  const cached = opened.get(key);
  if (cached && Date.now() - cached.at < CACHE_MS) return cached.db;

  const headers: Record<string, string> = {};
  if (fields.httpUsername) {
    headers.Authorization = `Basic ${Buffer.from(
      `${fields.httpUsername}:${fields.httpPassword ?? ""}`,
    ).toString("base64")}`;
  }
  const response = await fetch(source.baseUrl, {
    headers,
    timeoutMs: FETCH_TIMEOUT_MS,
    allowPrivateHosts: source.allowedPrivateHosts,
  });
  if (!response.ok) {
    throw new Error(
      `Downloading the KeePass file failed: HTTP ${response.status}`,
    );
  }
  const bytes = await response.arrayBuffer();
  if (bytes.byteLength > MAX_BYTES) {
    throw new Error("The KeePass file is larger than 10 MB");
  }
  const credentials = new kdbxweb.Credentials(
    fields.masterPassword
      ? kdbxweb.ProtectedValue.fromString(fields.masterPassword)
      : null,
    fields.keyFile ? Buffer.from(fields.keyFile, "base64") : null,
  );
  await credentials.ready;
  let db: kdbxweb.Kdbx;
  try {
    db = await kdbxweb.Kdbx.load(bytes, credentials);
  } catch (error) {
    const code = (error as { code?: string }).code;
    throw new Error(
      code === kdbxweb.Consts.ErrorCodes.InvalidKey
        ? "The KeePass master password or key file is wrong"
        : code === kdbxweb.Consts.ErrorCodes.BadSignature
          ? "That file is not a KeePass database"
          : "The KeePass file could not be opened",
    );
  }
  for (const [k, v] of opened)
    if (Date.now() - v.at >= CACHE_MS) opened.delete(k);
  opened.set(key, { db, at: Date.now() });
  return db;
}

const text = (value: kdbxweb.KdbxEntryField | undefined): string =>
  value === undefined
    ? ""
    : value instanceof kdbxweb.ProtectedValue
      ? value.getText()
      : String(value);

interface Found {
  entry: kdbxweb.KdbxEntry;
  path: string[];
}

/** Every entry outside the recycle bin, with the group names above it. */
function entries(db: kdbxweb.Kdbx): Found[] {
  const out: Found[] = [];
  const bin = db.meta.recycleBinUuid?.id;
  const walk = (group: kdbxweb.KdbxGroup, path: string[]) => {
    if (bin && group.uuid.id === bin) return;
    for (const entry of group.entries) out.push({ entry, path });
    for (const child of group.groups) walk(child, [...path, child.name ?? ""]);
  };
  walk(db.getDefaultGroup(), []);
  return out;
}

const refPath = (path: string[], title: string) =>
  [...path, title].map((part) => encodeURIComponent(part)).join("/");

export const keepassProvider: SecretProvider<KeepassReference> = {
  kind: "keepass",
  scheme: "kdbx",
  needsCredential: true,
  parseReference: parseKeepassReference,
  async resolve(fetch, source, ref) {
    const db = await open(fetch, source);
    const want = ref.groups.join("/");
    const found = entries(db).find(
      ({ entry, path }) =>
        path.join("/") === want &&
        text(entry.fields.get("Title")) === ref.title,
    );
    if (!found) throw new Error(`KeePass entry "${ref.title}" not found`);
    const name = fieldName(ref.field);
    if (!found.entry.fields.has(name)) {
      throw new Error(
        `KeePass entry "${ref.title}" has no field "${ref.field}"`,
      );
    }
    return text(found.entry.fields.get(name));
  },
  async test(fetch, source) {
    const db = await open(fetch, source);
    const count = entries(db).length;
    return `Opened, ${count} ${count === 1 ? "entry" : "entries"}`;
  },
  async listItems(fetch, source, search) {
    const db = await open(fetch, source);
    const needle = search.trim().toLowerCase();
    const items: PickItem[] = [];
    for (const { entry, path } of entries(db)) {
      const title = text(entry.fields.get("Title"));
      if (!title) continue;
      if (
        needle &&
        !`${path.join("/")}/${title}`.toLowerCase().includes(needle)
      ) {
        continue;
      }
      const base = `kdbx://${refPath(path, title)}`;
      items.push({
        id: entry.uuid.id,
        name: title,
        folder: path.length ? path.join(" / ") : null,
        username: text(entry.fields.get("UserName"))
          ? `${base}#UserName`
          : null,
        password: text(entry.fields.get("Password")) ? base : null,
      });
      if (items.length >= PICK_LIMIT) break;
    }
    return items.sort((a, b) => a.name.localeCompare(b.name));
  },
};

/** Forgets opened databases, for tests. */
export function clearKeepassCache(): void {
  opened.clear();
}
