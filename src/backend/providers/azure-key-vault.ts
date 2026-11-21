import {
  PICK_LIMIT,
  credentialFields,
  referenceParts,
  requestJson,
  trimBase,
  type PickItem,
  type ProviderSource,
  type SecretProvider,
} from "./types.js";

/**
 * Azure Key Vault with an app registration (client credentials). The
 * source URL is the vault, like https://my-vault.vault.azure.net.
 * azkv://<secret name>[/<version>]
 */
export interface AzureReference {
  name: string;
  version: string;
}

const API = "api-version=7.4";
const NAME = /^[0-9A-Za-z-]{1,127}$/;

export function parseAzureReference(raw: string): AzureReference | null {
  const parts = referenceParts(raw, "azkv");
  if (!parts || parts.length > 2 || !NAME.test(parts[0])) return null;
  return { name: parts[0], version: parts[1] ?? "" };
}

type Fetch = Parameters<SecretProvider["resolve"]>[0];

/** The authority to sign in at; other clouds can set their own. */
function authority(fields: Record<string, string>): string {
  return trimBase(fields.authority || "https://login.microsoftonline.com");
}

async function token(fetch: Fetch, source: ProviderSource): Promise<string> {
  const fields = credentialFields(source.credential);
  if (!fields.tenantId || !fields.clientId || !fields.clientSecret) {
    throw new Error("Azure needs a tenant id, client id and client secret");
  }
  if (!/^[0-9A-Za-z.-]+$/.test(fields.tenantId)) {
    throw new Error("The Azure tenant id is not valid");
  }
  const result = await requestJson<{ access_token?: string }>(
    fetch,
    source,
    `${authority(fields)}/${fields.tenantId}/oauth2/v2.0/token`,
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: fields.clientId,
        client_secret: fields.clientSecret,
        scope: "https://vault.azure.net/.default",
      }).toString(),
      label: "Azure sign in",
    },
  );
  if (!result.access_token) throw new Error("Azure sign in gave no token");
  return result.access_token;
}

async function listPage(
  fetch: Fetch,
  source: ProviderSource,
  url: string,
  bearer: string,
) {
  return requestJson<{
    value?: Array<{ id?: string; contentType?: string }>;
    nextLink?: string | null;
  }>(fetch, source, url, {
    headers: { Authorization: `Bearer ${bearer}` },
    label: "Azure secret list",
  });
}

export const azureKeyVaultProvider: SecretProvider<AzureReference> = {
  kind: "azure-key-vault",
  scheme: "azkv",
  needsCredential: true,
  parseReference: parseAzureReference,
  async resolve(fetch, source, ref) {
    const bearer = await token(fetch, source);
    const version = ref.version ? `/${encodeURIComponent(ref.version)}` : "";
    const result = await requestJson<{ value?: string }>(
      fetch,
      source,
      `${trimBase(source.baseUrl)}/secrets/${ref.name}${version}?${API}`,
      {
        headers: { Authorization: `Bearer ${bearer}` },
        label: `Azure secret "${ref.name}"`,
      },
    );
    if (typeof result.value !== "string") {
      throw new Error(`Azure secret "${ref.name}" has no value`);
    }
    return result.value;
  },
  async test(fetch, source) {
    const bearer = await token(fetch, source);
    await listPage(
      fetch,
      source,
      `${trimBase(source.baseUrl)}/secrets?maxresults=1&${API}`,
      bearer,
    );
    return "Signed in and the vault answered";
  },
  async listItems(fetch, source, search) {
    const bearer = await token(fetch, source);
    const needle = search.trim().toLowerCase();
    const items: PickItem[] = [];
    // A nextLink must stay on the vault, so a reply can't send the token elsewhere.
    const vault = new URL(trimBase(source.baseUrl)).origin;
    let url: string | null =
      `${trimBase(source.baseUrl)}/secrets?maxresults=25&${API}`;
    for (
      let pages = 0;
      url && pages < 20 && items.length < PICK_LIMIT;
      pages++
    ) {
      const page = await listPage(fetch, source, url, bearer);
      for (const secret of page.value ?? []) {
        const name = secret.id?.split("/").pop();
        if (!name || (needle && !name.toLowerCase().includes(needle))) continue;
        items.push({
          id: name,
          name,
          folder: null,
          username: null,
          password: `azkv://${name}`,
        });
      }
      url =
        page.nextLink && new URL(page.nextLink).origin === vault
          ? page.nextLink
          : null;
    }
    return items
      .slice(0, PICK_LIMIT)
      .sort((a, b) => a.name.localeCompare(b.name));
  },
};
