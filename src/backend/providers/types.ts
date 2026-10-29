import type { PluginFetch } from "@termix-ssh/plugin-sdk/backend";

/** What a provider gets to reach its server. */
export interface ProviderSource {
  baseUrl: string;
  /** The stored credential: a token, or JSON for providers with several fields. */
  credential: string;
  allowedPrivateHosts: readonly string[];
}

export interface SecretProvider<Ref = unknown> {
  kind: string;
  /** The reference prefix, as in "op" for op://vault/item/field. */
  scheme: string;
  /** Whether a source of this kind needs a stored credential. */
  needsCredential: boolean;
  parseReference: (raw: string) => Ref | null;
  resolve: (
    fetch: PluginFetch,
    source: ProviderSource,
    ref: Ref,
  ) => Promise<string>;
  /** Checks the server and credential. Returns a short description of what it found. */
  test: (fetch: PluginFetch, source: ProviderSource) => Promise<string>;
}

export const FETCH_TIMEOUT_MS = 10_000;

/** The credential as JSON fields, or an empty object when it is not JSON. */
export function credentialFields(credential: string): Record<string, string> {
  try {
    const parsed = JSON.parse(credential);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return {};
    }
    return Object.fromEntries(
      Object.entries(parsed).filter(
        (entry): entry is [string, string] => typeof entry[1] === "string",
      ),
    );
  } catch {
    return {};
  }
}

export function trimBase(baseUrl: string): string {
  return baseUrl.replace(/\/+$/, "");
}

/** A JSON request through ctx.fetch that throws on a non 2xx answer. */
export async function requestJson<T>(
  fetch: PluginFetch,
  source: Pick<ProviderSource, "allowedPrivateHosts">,
  url: string,
  init: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    label: string;
  },
): Promise<T> {
  const response = await fetch(url, {
    method: init.method ?? "GET",
    headers: init.headers,
    body: init.body,
    timeoutMs: FETCH_TIMEOUT_MS,
    allowPrivateHosts: source.allowedPrivateHosts,
  });
  if (!response.ok) {
    throw new Error(`${init.label} failed: HTTP ${response.status}`);
  }
  return (await response.json()) as T;
}

/** Splits "scheme://a/b/c" into its decoded path parts, or null. */
export function referenceParts(raw: string, scheme: string): string[] | null {
  const prefix = `${scheme}://`;
  const value = raw.trim();
  if (!value.toLowerCase().startsWith(prefix)) return null;
  const rest = value.slice(prefix.length).split("?")[0];
  try {
    const parts = rest.split("/").map((part) => decodeURIComponent(part));
    return parts.every((part) => part.length > 0) ? parts : null;
  } catch {
    return null;
  }
}
