import {
  parseBitwardenCliReference,
  type BitwardenCliReference,
} from "./bitwarden-cli.js";
import { bitwardenEndpoints } from "./bitwarden-sm.js";
import {
  FETCH_TIMEOUT_MS,
  type ProviderSource,
  type SecretProvider,
} from "./types.js";
import {
  decryptItems,
  findItem,
  readField,
  vaultPickItems,
  type OpenVault,
} from "../bitwarden/vault-items.js";
import { UnlockRequiredError } from "../bitwarden/vault-sessions.js";

/**
 * A Bitwarden or Vaultwarden server each Termix user unlocks with their own
 * account, so a bw:// reference resolves with that user's own access. Same
 * references as the bw serve source.
 */

function openVault(source: ProviderSource): Promise<OpenVault> {
  if (!source.vault) throw new UnlockRequiredError();
  return source.vault();
}

export const bitwardenVaultProvider: SecretProvider<BitwardenCliReference> = {
  kind: "bitwarden-vault",
  scheme: "bw",
  needsCredential: false,
  perUser: true,
  parseReference: parseBitwardenCliReference,
  async resolve(_fetch, source, ref) {
    const vault = await openVault(source);
    return readField(findItem(decryptItems(vault), ref.item), ref.field);
  },
  async listItems(_fetch, source, search) {
    const vault = await openVault(source);
    return vaultPickItems(vault, decryptItems(vault), search);
  },
  async test(fetch, source) {
    if (source.vault) {
      try {
        const vault = await source.vault();
        return `Unlocked, ${decryptItems(vault).length} items`;
      } catch (error) {
        if (!(error instanceof UnlockRequiredError)) throw error;
      }
    }
    const response = await fetch(
      `${bitwardenEndpoints(source.baseUrl).api}/config`,
      {
        timeoutMs: FETCH_TIMEOUT_MS,
        allowPrivateHosts: source.allowedPrivateHosts,
      },
    );
    if (!response.ok) {
      throw new Error(`Bitwarden server check failed: HTTP ${response.status}`);
    }
    return "Server reachable. Unlock your vault to use it";
  },
};
