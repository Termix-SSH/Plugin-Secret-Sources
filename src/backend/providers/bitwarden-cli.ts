import {
  referenceParts,
  requestJson,
  trimBase,
  type ProviderSource,
  type SecretProvider,
} from "./types.js";
import type { PluginFetch } from "@termix-ssh/plugin-sdk/backend";

/**
 * A Bitwarden or Vaultwarden vault through the Bitwarden CLI's `bw serve`,
 * which keeps the vault unlocked and does the decryption itself.
 * bw://<item name or id>/<field>, where field is username, password, totp,
 * notes, uri or the name of a custom field.
 */
export interface BitwardenCliReference {
  item: string;
  field: string;
}

export function parseBitwardenCliReference(
  raw: string,
): BitwardenCliReference | null {
  const parts = referenceParts(raw, "bw");
  if (!parts || parts.length !== 2) return null;
  return { item: parts[0], field: parts[1] };
}

interface BwItem {
  id: string;
  name: string;
  notes?: string | null;
  login?: {
    username?: string | null;
    password?: string | null;
    totp?: string | null;
    uris?: Array<{ uri?: string | null }>;
  } | null;
  fields?: Array<{ name?: string | null; value?: string | null }>;
}

interface BwAnswer<T> {
  success: boolean;
  message?: string;
  data?: T;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

async function bw<T>(
  fetch: PluginFetch,
  source: ProviderSource,
  path: string,
  label: string,
): Promise<T> {
  const answer = await requestJson<BwAnswer<T>>(
    fetch,
    source,
    `${trimBase(source.baseUrl)}${path}`,
    {
      headers: source.credential
        ? { Authorization: `Bearer ${source.credential}` }
        : {},
      label,
    },
  );
  if (!answer.success || answer.data === undefined) {
    throw new Error(answer.message || `${label} failed`);
  }
  return answer.data;
}

async function findItem(
  fetch: PluginFetch,
  source: ProviderSource,
  item: string,
): Promise<BwItem> {
  if (UUID.test(item)) {
    return bw<BwItem>(
      fetch,
      source,
      `/object/item/${encodeURIComponent(item)}`,
      "Bitwarden item",
    );
  }
  const list = await bw<{ data?: BwItem[] }>(
    fetch,
    source,
    `/list/object/items?search=${encodeURIComponent(item)}`,
    "Bitwarden search",
  );
  const matches = (list.data ?? []).filter(
    (candidate) => candidate.name.toLowerCase() === item.toLowerCase(),
  );
  if (matches.length === 0) {
    throw new Error(`Bitwarden item "${item}" not found`);
  }
  if (matches.length > 1) {
    throw new Error(`More than one Bitwarden item is named "${item}"`);
  }
  return matches[0];
}

export const bitwardenCliProvider: SecretProvider<BitwardenCliReference> = {
  kind: "bitwarden-cli",
  scheme: "bw",
  needsCredential: false,
  parseReference: parseBitwardenCliReference,
  async resolve(fetch, source, ref) {
    const item = await findItem(fetch, source, ref.item);
    const field = ref.field.toLowerCase();
    let value: string | null | undefined;
    if (field === "username") value = item.login?.username;
    else if (field === "password") value = item.login?.password;
    else if (field === "notes") value = item.notes;
    else if (field === "uri") value = item.login?.uris?.[0]?.uri;
    else if (field === "totp") {
      value = (
        await bw<{ data?: string }>(
          fetch,
          source,
          `/object/totp/${encodeURIComponent(item.id)}`,
          "Bitwarden TOTP",
        )
      ).data;
    } else {
      value = item.fields?.find(
        (f) => (f.name ?? "").toLowerCase() === field,
      )?.value;
    }
    if (value === null || value === undefined) {
      throw new Error(
        `Bitwarden field "${ref.field}" not found on "${item.name}"`,
      );
    }
    return value;
  },
  async test(fetch, source) {
    const status = await bw<{ template?: { status?: string } }>(
      fetch,
      source,
      "/status",
      "Bitwarden status",
    );
    const state = status.template?.status;
    if (state !== "unlocked") {
      throw new Error(
        `The vault is ${state ?? "not ready"}. Unlock it in bw serve`,
      );
    }
    return "Vault unlocked";
  },
};
