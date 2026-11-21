import type { PluginContext } from "@termix-ssh/plugin-sdk/backend";
import type {
  SecretSourceRecord,
  SecretSourceRepository,
} from "./repository.js";
import type { TokenStore } from "./token-store.js";
import { parseAllowlist } from "./egress.js";
import {
  PROVIDERS,
  kindsForScheme,
  providerForKind,
  type ProviderSource,
  type SecretProvider,
} from "./providers/index.js";
import { UNLOCK_TAB, type VaultSessions } from "./bitwarden/vault-sessions.js";

/** The user's own source of these kinds first, else a shared one. */
export async function pickSecretSource(
  repository: SecretSourceRepository,
  userId: string,
  kinds: string | string[],
) {
  const wanted = Array.isArray(kinds) ? kinds : [kinds];
  const sources = (await repository.listVisibleToUser(userId)).filter(
    (source) => wanted.includes(source.kind),
  );
  return (
    sources.find((source) => source.userId === userId) ?? sources[0] ?? null
  );
}

export interface SourceDeps {
  ctx: PluginContext;
  tokenStore: TokenStore;
  sessions: VaultSessions;
}

/**
 * What a provider needs to reach a source for a user: the owner's stored
 * credential, the private hosts an admin allowed, and for per-user kinds
 * that user's own unlocked vault.
 */
export async function providerSourceFor(
  deps: SourceDeps,
  source: SecretSourceRecord,
  userId: string,
): Promise<ProviderSource> {
  const credential =
    (await deps.tokenStore.getForOwner(source.id, source.userId)) ?? "";
  const target = {
    baseUrl: source.baseUrl,
    credential,
    allowedPrivateHosts: parseAllowlist(
      await deps.ctx.settings.get<string>("privateEndpoints"),
    ),
  };
  const provider = providerForKind(source.kind);
  if (!provider?.perUser) return target;
  return {
    ...target,
    vault: () =>
      deps.sessions.open(
        { id: source.id, baseUrl: source.baseUrl, credential },
        userId,
        target,
      ),
  };
}

type RegisterWithOptions = (
  scheme: string,
  resolve: (userId: string, reference: string) => Promise<string>,
  options?: { unlockTab?: string },
) => void;

function registerResolver(
  deps: SourceDeps,
  repository: SecretSourceRepository,
  scheme: string,
  parse: SecretProvider["parseReference"],
): void {
  const kinds = kindsForScheme(scheme);
  // The third argument is Termix 26.11.3; older cores ignore it.
  (deps.ctx.credentials.registerSecretResolver as RegisterWithOptions)(
    scheme,
    async (userId, reference) => {
      const ref = parse(reference);
      if (!ref) throw new Error(`Invalid secret reference: ${reference}`);

      const source = await pickSecretSource(repository, userId, kinds);
      const provider = source ? providerForKind(source.kind) : undefined;
      if (!source || !provider) {
        throw new Error(
          `This host uses a ${scheme}:// secret reference but no secret source is configured for it`,
        );
      }

      const target = await providerSourceFor(deps, source, userId);
      if (!target.credential && provider.needsCredential) {
        throw new Error(
          "No token is stored for this secret source. Its owner needs to save the token again",
        );
      }
      return provider.resolve(deps.ctx.fetch, target, ref);
    },
    kinds.some((kind) => providerForKind(kind)?.perUser)
      ? { unlockTab: UNLOCK_TAB }
      : undefined,
  );
}

/** One resolver per scheme: op://, infisical://, bws://, vault://, bw:// and so on. */
export function registerSecretResolvers(
  deps: SourceDeps,
  repository: SecretSourceRepository,
): void {
  const seen = new Set<string>();
  for (const provider of PROVIDERS) {
    if (seen.has(provider.scheme)) continue;
    seen.add(provider.scheme);
    // Kinds sharing a scheme share its reference syntax.
    registerResolver(
      deps,
      repository,
      provider.scheme,
      provider.parseReference,
    );
  }
}
