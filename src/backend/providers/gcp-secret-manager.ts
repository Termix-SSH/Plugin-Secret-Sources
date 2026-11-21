import crypto from "node:crypto";
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
 * Google Cloud Secret Manager with a service account key. The source URL is
 * the API, https://secretmanager.googleapis.com.
 * gcpsm://<project>/<secret>[/<version>]
 */
export interface GcpReference {
  project: string;
  secret: string;
  version: string;
}

const ID = /^[A-Za-z0-9_.:-]{1,255}$/;
const DEFAULT_TOKEN_URI = "https://oauth2.googleapis.com/token";

export function parseGcpReference(raw: string): GcpReference | null {
  const parts = referenceParts(raw, "gcpsm");
  if (!parts || parts.length < 2 || parts.length > 3) return null;
  if (!parts.every((part) => ID.test(part))) return null;
  return { project: parts[0], secret: parts[1], version: parts[2] ?? "latest" };
}

interface ServiceAccount {
  client_email: string;
  private_key: string;
  project_id?: string;
  token_uri?: string;
}

function serviceAccount(source: ProviderSource): ServiceAccount {
  const { serviceAccountJson } = credentialFields(source.credential);
  let parsed: Partial<ServiceAccount>;
  try {
    parsed = JSON.parse(serviceAccountJson ?? "") as Partial<ServiceAccount>;
  } catch {
    throw new Error(
      "The service account key must be the JSON file from Google",
    );
  }
  if (!parsed.client_email || !parsed.private_key) {
    throw new Error(
      "The service account key has no client_email or private_key",
    );
  }
  return parsed as ServiceAccount;
}

const b64url = (data: Buffer | string) =>
  Buffer.from(data).toString("base64url");

/** A signed JWT asking for a cloud-platform token. */
export function assertion(account: ServiceAccount, now = Date.now()): string {
  const iat = Math.floor(now / 1000);
  const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claims = b64url(
    JSON.stringify({
      iss: account.client_email,
      scope: "https://www.googleapis.com/auth/cloud-platform",
      aud: account.token_uri || DEFAULT_TOKEN_URI,
      iat,
      exp: iat + 3600,
    }),
  );
  const signature = crypto
    .createSign("RSA-SHA256")
    .update(`${header}.${claims}`)
    .sign(account.private_key);
  return `${header}.${claims}.${b64url(signature)}`;
}

type Fetch = Parameters<SecretProvider["resolve"]>[0];

async function token(fetch: Fetch, source: ProviderSource): Promise<string> {
  const account = serviceAccount(source);
  const tokenUri = account.token_uri || DEFAULT_TOKEN_URI;
  if (!/^https:\/\//.test(tokenUri)) {
    throw new Error("The service account token_uri must be https");
  }
  const result = await requestJson<{ access_token?: string }>(
    fetch,
    source,
    tokenUri,
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion: assertion(account),
      }).toString(),
      label: "Google sign in",
    },
  );
  if (!result.access_token) throw new Error("Google sign in gave no token");
  return result.access_token;
}

export const gcpSecretManagerProvider: SecretProvider<GcpReference> = {
  kind: "gcp-secret-manager",
  scheme: "gcpsm",
  needsCredential: true,
  parseReference: parseGcpReference,
  async resolve(fetch, source, ref) {
    const bearer = await token(fetch, source);
    const result = await requestJson<{ payload?: { data?: string } }>(
      fetch,
      source,
      `${trimBase(source.baseUrl)}/v1/projects/${ref.project}/secrets/${ref.secret}/versions/${ref.version}:access`,
      {
        headers: { Authorization: `Bearer ${bearer}` },
        label: `Google secret "${ref.secret}"`,
      },
    );
    if (typeof result.payload?.data !== "string") {
      throw new Error(`Google secret "${ref.secret}" has no value`);
    }
    return Buffer.from(result.payload.data, "base64").toString("utf8");
  },
  async test(fetch, source) {
    await token(fetch, source);
    return `Signed in as ${serviceAccount(source).client_email}`;
  },
  async listItems(fetch, source, search) {
    const account = serviceAccount(source);
    if (!account.project_id || !ID.test(account.project_id)) {
      throw new Error("The service account key has no project_id");
    }
    const bearer = await token(fetch, source);
    const needle = search.trim().toLowerCase();
    const items: PickItem[] = [];
    let pageToken = "";
    for (let pages = 0; pages < 20 && items.length < PICK_LIMIT; pages++) {
      const query = new URLSearchParams({ pageSize: "100" });
      if (pageToken) query.set("pageToken", pageToken);
      const page = await requestJson<{
        secrets?: Array<{ name?: string }>;
        nextPageToken?: string;
      }>(
        fetch,
        source,
        `${trimBase(source.baseUrl)}/v1/projects/${account.project_id}/secrets?${query}`,
        {
          headers: { Authorization: `Bearer ${bearer}` },
          label: "Google secret list",
        },
      );
      for (const secret of page.secrets ?? []) {
        const name = secret.name?.split("/").pop();
        if (!name || (needle && !name.toLowerCase().includes(needle))) continue;
        items.push({
          id: secret.name ?? name,
          name,
          folder: account.project_id,
          username: null,
          password: `gcpsm://${account.project_id}/${name}`,
        });
      }
      if (!page.nextPageToken) break;
      pageToken = page.nextPageToken;
    }
    return items
      .slice(0, PICK_LIMIT)
      .sort((a, b) => a.name.localeCompare(b.name));
  },
};
