import {
  credentialFields,
  requestJson,
  trimBase,
  type ProviderSource,
  type SecretProvider,
} from "./types.js";
import type { PluginFetch } from "@termix-ssh/plugin-sdk/backend";

/**
 * HashiCorp Vault (or OpenBao) KV secrets, version 1 or 2, with a token or an
 * AppRole role id and secret id.
 * vault://<mount>/<path/to/secret>#<key>
 */
export interface VaultReference {
  mount: string;
  path: string;
  key: string;
}

export function parseVaultReference(raw: string): VaultReference | null {
  const match = /^vault:\/\/([^/#?]+)\/([^#?]+)#([^#?]+)$/i.exec(raw.trim());
  if (!match) return null;
  try {
    return {
      mount: decodeURIComponent(match[1]),
      path: match[2]
        .split("/")
        .filter(Boolean)
        .map((part) => decodeURIComponent(part))
        .join("/"),
      key: decodeURIComponent(match[3]),
    };
  } catch {
    return null;
  }
}

function pathOf(...parts: string[]): string {
  return parts
    .flatMap((part) => part.split("/"))
    .filter(Boolean)
    .map(encodeURIComponent)
    .join("/");
}

async function vaultToken(
  fetch: PluginFetch,
  source: ProviderSource,
): Promise<{ token: string; headers: Record<string, string> }> {
  const fields = credentialFields(source.credential);
  const token = fields.token || (fields.roleId ? "" : source.credential.trim());
  const headers: Record<string, string> = fields.namespace
    ? { "X-Vault-Namespace": fields.namespace }
    : {};
  if (token) return { token, headers };
  if (!fields.roleId || !fields.secretId) {
    throw new Error("Vault needs a token, or an AppRole role id and secret id");
  }
  const login = await requestJson<{ auth?: { client_token?: string } }>(
    fetch,
    source,
    `${trimBase(source.baseUrl)}/v1/auth/${pathOf(fields.approleMount || "approle")}/login`,
    {
      method: "POST",
      headers: { ...headers, "Content-Type": "application/json" },
      body: JSON.stringify({
        role_id: fields.roleId,
        secret_id: fields.secretId,
      }),
      label: "Vault AppRole login",
    },
  );
  const clientToken = login.auth?.client_token;
  if (!clientToken) throw new Error("Vault AppRole login gave no token");
  return { token: clientToken, headers };
}

async function readKv(
  fetch: PluginFetch,
  source: ProviderSource,
  headers: Record<string, string>,
  url: string,
): Promise<Record<string, unknown> | null> {
  const response = await fetch(url, {
    headers,
    timeoutMs: 10_000,
    allowPrivateHosts: source.allowedPrivateHosts,
  });
  if (response.status === 404) return null;
  if (!response.ok) {
    throw new Error(`Vault read failed: HTTP ${response.status}`);
  }
  return (await response.json()) as Record<string, unknown>;
}

export const vaultProvider: SecretProvider<VaultReference> = {
  kind: "hashicorp-vault",
  scheme: "vault",
  needsCredential: true,
  parseReference: parseVaultReference,
  async resolve(fetch, source, ref) {
    const { token, headers } = await vaultToken(fetch, source);
    const auth = { ...headers, "X-Vault-Token": token };
    const base = `${trimBase(source.baseUrl)}/v1`;
    // KV v2 keeps the data under <mount>/data/<path>; v1 at <mount>/<path>.
    const v2 = await readKv(
      fetch,
      source,
      auth,
      `${base}/${pathOf(ref.mount, "data", ref.path)}`,
    );
    const v2Data = (v2?.data as { data?: Record<string, unknown> } | undefined)
      ?.data;
    let data: Record<string, unknown> | undefined = v2Data;
    if (!data) {
      const v1 = await readKv(
        fetch,
        source,
        auth,
        `${base}/${pathOf(ref.mount, ref.path)}`,
      );
      data = v1?.data as Record<string, unknown> | undefined;
    }
    if (!data) {
      throw new Error(`Vault secret "${ref.mount}/${ref.path}" not found`);
    }
    const value = data[ref.key];
    if (typeof value !== "string") {
      throw new Error(`Vault key "${ref.key}" not found in "${ref.path}"`);
    }
    return value;
  },
  async test(fetch, source) {
    const { token, headers } = await vaultToken(fetch, source);
    const self = await requestJson<{ data?: { display_name?: string } }>(
      fetch,
      source,
      `${trimBase(source.baseUrl)}/v1/auth/token/lookup-self`,
      {
        headers: { ...headers, "X-Vault-Token": token },
        label: "Vault token lookup",
      },
    );
    return self.data?.display_name
      ? `Signed in as ${self.data.display_name}`
      : "Signed in";
  },
};
