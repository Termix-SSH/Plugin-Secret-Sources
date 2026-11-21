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

export interface PickItem {
  id: string;
  name: string;
  folder: string | null;
  username: string | null;
  password: string | null;
}

export interface VaultSession {
  unlocked: boolean;
  email: string | null;
  method: "sso" | "password" | "apikey" | null;
  expiresAt: number | null;
}

export type UnlockBody =
  | {
      method: "password";
      email: string;
      password: string;
      twoFactorProvider?: number;
      twoFactorCode?: string;
    }
  | {
      method: "apikey";
      clientId: string;
      clientSecret: string;
      password: string;
    }
  | { method: "sso"; redirect: string; password: string };

export interface ReferenceTestResult {
  ok: boolean;
  status:
    | "found"
    | "invalid"
    | "no_source"
    | "not_found"
    | "denied"
    | "connection"
    | "locked";
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
    items: (id: string, search: string) =>
      data(
        api.get<{ items: PickItem[] }>(
          `/${id}/items?search=${encodeURIComponent(search)}`,
        ),
      ).then((r) => r.items),
    session: (id: string) => data(api.get<VaultSession>(`/${id}/session`)),
    unlock: (id: string, body: UnlockBody) =>
      data(api.post<VaultSession>(`/${id}/session`, body)),
    startSso: (id: string) =>
      data(api.post<{ url: string }>(`/${id}/session/sso`)).then((r) => r.url),
    lock: (id: string) =>
      data(api.delete<{ success: boolean }>(`/${id}/session`)),
    testReference: (reference: string) =>
      data(api.post<ReferenceTestResult>("/test-reference", { reference })),
  };
}

export type SecretSourcesApi = ReturnType<typeof createSecretSourcesApi>;
