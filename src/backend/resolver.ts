import type { PluginContext } from "@termix-ssh/plugin-sdk/backend";
import type { SecretSourceRepository } from "./repository.js";
import type { TokenStore } from "./token-store.js";
import { parseAllowlist } from "./egress.js";
import { PROVIDERS, type SecretProvider } from "./providers/index.js";

/** The user's own source of this kind first, else a shared one. */
export async function pickSecretSource(
  repository: SecretSourceRepository,
  userId: string,
  kind: string,
) {
  const sources = (await repository.listVisibleToUser(userId)).filter(
    (source) => source.kind === kind,
  );
  return (
    sources.find((source) => source.userId === userId) ?? sources[0] ?? null
  );
}

function registerResolver(
  ctx: PluginContext,
  repository: SecretSourceRepository,
  tokenStore: TokenStore,
  provider: SecretProvider,
): void {
  ctx.credentials.registerSecretResolver(
    provider.scheme,
    async (userId, reference) => {
      const ref = provider.parseReference(reference);
      if (!ref) throw new Error(`Invalid secret reference: ${reference}`);

      const source = await pickSecretSource(repository, userId, provider.kind);
      if (!source) {
        throw new Error(
          `This host uses a ${provider.scheme}:// secret reference but no secret source is configured for it`,
        );
      }

      const credential = await tokenStore.getForOwner(source.id, source.userId);
      if (!credential && provider.needsCredential) {
        throw new Error(
          "No token is stored for this secret source. Its owner needs to save the token again",
        );
      }

      return provider.resolve(
        ctx.fetch,
        {
          baseUrl: source.baseUrl,
          credential: credential ?? "",
          allowedPrivateHosts: parseAllowlist(
            await ctx.settings.get<string>("privateEndpoints"),
          ),
        },
        ref,
      );
    },
  );
}

/** One resolver per scheme: op://, infisical://, bws://, vault:// and bw://. */
export function registerSecretResolvers(
  ctx: PluginContext,
  repository: SecretSourceRepository,
  tokenStore: TokenStore,
): void {
  for (const provider of PROVIDERS) {
    registerResolver(ctx, repository, tokenStore, provider);
  }
}
