import type { PluginApiClient } from "@termix-ssh/plugin-sdk/frontend";
import type { SecretSourceKind } from "./source-kinds";

export interface SecretSource {
  id: string;
  name: string;
  kind: SecretSourceKind;
  baseUrl: string;
  shared: boolean;
  owned: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface SecretSourceInput {
  name: string;
  kind: SecretSourceKind;
  baseUrl: string;
  token: string;
  shared?: boolean;
}

export interface SecretSourceUpdateInput {
  name?: string;
  baseUrl?: string;
  token?: string;
  shared?: boolean;
}

export interface ReferenceTestResult {
  ok: boolean;
  status:
    "found" | "invalid" | "no_source" | "not_found" | "denied" | "connection";
  source?: string;
  error?: string;
}

/** The secret-sources routes, through the plugin's own client. */
export function createSecretSourcesApi(api: PluginApiClient) {
  const data = async <T>(request: Promise<{ data: T }>) => (await request).data;

  return {
    list: () =>
      data(api.get<{ sources: SecretSource[] }>("/")).then((r) => r.sources),
    create: (body: SecretSourceInput) =>
      data(api.post<{ source: SecretSource }>("/", body)).then((r) => r.source),
    update: (id: string, body: SecretSourceUpdateInput) =>
      data(api.put<{ success: boolean }>(`/${id}`, body)),
    remove: (id: string) => data(api.delete<{ success: boolean }>(`/${id}`)),
    test: (id: string) =>
      data(
        api.post<{ ok: boolean; detail?: string; error?: string }>(
          `/${id}/test`,
        ),
      ),
    testReference: (reference: string) =>
      data(api.post<ReferenceTestResult>("/test-reference", { reference })),
  };
}

type SecretSourcesApi = ReturnType<typeof createSecretSourcesApi>;
