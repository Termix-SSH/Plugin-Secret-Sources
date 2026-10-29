import { bitwardenCliProvider } from "./bitwarden-cli.js";
import { bitwardenSmProvider } from "./bitwarden-sm.js";
import { vaultProvider } from "./hashicorp-vault.js";
import { infisicalProvider } from "./infisical.js";
import { onePasswordProvider } from "./onepassword.js";
import type { SecretProvider } from "./types.js";

export const PROVIDERS = [
  onePasswordProvider,
  infisicalProvider,
  bitwardenSmProvider,
  vaultProvider,
  bitwardenCliProvider,
] as SecretProvider[];

export const KINDS = PROVIDERS.map((provider) => provider.kind);

export function providerForKind(kind: string): SecretProvider | undefined {
  return PROVIDERS.find((provider) => provider.kind === kind);
}

export type { ProviderSource, SecretProvider } from "./types.js";
