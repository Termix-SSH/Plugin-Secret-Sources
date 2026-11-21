import { awsSecretsManagerProvider } from "./aws-secrets-manager.js";
import { azureKeyVaultProvider } from "./azure-key-vault.js";
import { bitwardenCliProvider } from "./bitwarden-cli.js";
import { bitwardenSmProvider } from "./bitwarden-sm.js";
import { bitwardenVaultProvider } from "./bitwarden-vault.js";
import { vaultProvider } from "./hashicorp-vault.js";
import { gcpSecretManagerProvider } from "./gcp-secret-manager.js";
import { infisicalProvider } from "./infisical.js";
import { keepassProvider } from "./keepass.js";
import { onePasswordProvider } from "./onepassword.js";
import type { SecretProvider } from "./types.js";

export const PROVIDERS = [
  onePasswordProvider,
  infisicalProvider,
  bitwardenSmProvider,
  vaultProvider,
  bitwardenCliProvider,
  bitwardenVaultProvider,
  keepassProvider,
  awsSecretsManagerProvider,
  azureKeyVaultProvider,
  gcpSecretManagerProvider,
] as SecretProvider[];

export const KINDS = PROVIDERS.map((provider) => provider.kind);

/** The kinds that resolve one reference scheme. */
export function kindsForScheme(scheme: string): string[] {
  return PROVIDERS.filter((provider) => provider.scheme === scheme).map(
    (provider) => provider.kind,
  );
}

export function providerForKind(kind: string): SecretProvider | undefined {
  return PROVIDERS.find((provider) => provider.kind === kind);
}

export type { ProviderSource, SecretProvider } from "./types.js";
