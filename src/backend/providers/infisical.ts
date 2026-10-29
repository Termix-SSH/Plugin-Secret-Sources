import {
  credentialFields,
  referenceParts,
  requestJson,
  trimBase,
  type SecretProvider,
} from "./types.js";

/**
 * Infisical, cloud or self-hosted, with a machine identity's Universal Auth
 * client id and secret.
 * infisical://<project id>/<environment>/<optional/folder/path>/<SECRET_NAME>
 */
export interface InfisicalReference {
  projectId: string;
  environment: string;
  path: string;
  name: string;
}

export function parseInfisicalReference(
  raw: string,
): InfisicalReference | null {
  const parts = referenceParts(raw, "infisical");
  if (!parts || parts.length < 3) return null;
  const [projectId, environment, ...rest] = parts;
  const name = rest.pop()!;
  return { projectId, environment, path: `/${rest.join("/")}`, name };
}

async function login(
  fetch: Parameters<SecretProvider["resolve"]>[0],
  source: Parameters<SecretProvider["resolve"]>[1],
): Promise<string> {
  const { clientId, clientSecret } = credentialFields(source.credential);
  if (!clientId || !clientSecret) {
    throw new Error("Infisical needs a client id and client secret");
  }
  const result = await requestJson<{ accessToken?: string }>(
    fetch,
    source,
    `${trimBase(source.baseUrl)}/api/v1/auth/universal-auth/login`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ clientId, clientSecret }),
      label: "Infisical login",
    },
  );
  if (!result.accessToken) throw new Error("Infisical login gave no token");
  return result.accessToken;
}

export const infisicalProvider: SecretProvider<InfisicalReference> = {
  kind: "infisical",
  scheme: "infisical",
  needsCredential: true,
  parseReference: parseInfisicalReference,
  async resolve(fetch, source, ref) {
    const token = await login(fetch, source);
    const query = new URLSearchParams({
      workspaceId: ref.projectId,
      environment: ref.environment,
      secretPath: ref.path,
    });
    const result = await requestJson<{
      secret?: { secretValue?: string };
    }>(
      fetch,
      source,
      `${trimBase(source.baseUrl)}/api/v3/secrets/raw/${encodeURIComponent(ref.name)}?${query}`,
      {
        headers: { Authorization: `Bearer ${token}` },
        label: `Infisical secret "${ref.name}"`,
      },
    );
    const value = result.secret?.secretValue;
    if (value === undefined) {
      throw new Error(`Infisical secret "${ref.name}" not found`);
    }
    return value;
  },
  async test(fetch, source) {
    await login(fetch, source);
    return "Signed in";
  },
};
