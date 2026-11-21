import type { Router } from "express";
import type { PluginContext } from "@termix-ssh/plugin-sdk/backend";
import { sources } from "./tables.js";
import { createSecretSourceRepository } from "./repository.js";
import { createTokenStore } from "./token-store.js";
import { registerSecretSourceRoutes } from "./routes.js";
import { registerSecretResolvers } from "./resolver.js";
import { createVaultSessions } from "./bitwarden/vault-sessions.js";

export async function activate(ctx: PluginContext) {
  const table = await ctx.db.define(sources);
  const repository = createSecretSourceRepository(ctx.db, table);
  const deps = {
    ctx,
    tokenStore: createTokenStore(ctx),
    sessions: createVaultSessions(ctx),
  };

  registerSecretSourceRoutes(ctx.http.router<Router>(), deps, repository);
  registerSecretResolvers(deps, repository);

  ctx.log.info("Secret sources routes mounted at /plugin-api/secret-sources");
}

export async function deactivate() {
  // Everything above was registered through ctx and is disposed by core.
}
