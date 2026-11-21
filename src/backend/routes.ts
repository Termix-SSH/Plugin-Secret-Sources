import { randomUUID } from "node:crypto";
import type { Request, Response, Router } from "express";
import type { SecretSourceRepository } from "./repository.js";
import { parseAllowlist } from "./egress.js";
import {
  KINDS,
  PROVIDERS,
  kindsForScheme,
  providerForKind,
} from "./providers/index.js";
import {
  pickSecretSource,
  providerSourceFor,
  type SourceDeps,
} from "./resolver.js";
import {
  UnlockRequiredError,
  type UnlockInput,
} from "./bitwarden/vault-sessions.js";
import { VaultLoginError } from "./bitwarden/vault-client.js";

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function validBaseUrl(raw: unknown): string | null {
  if (!isNonEmptyString(raw)) return null;
  try {
    const url = new URL(raw.trim());
    if (!["http:", "https:"].includes(url.protocol)) return null;
    return url.toString().replace(/\/+$/, "");
  } catch {
    return null;
  }
}

/** Sorts a failed lookup into what the person can do about it. */
function referenceFailure(
  message: string,
): "not_found" | "denied" | "connection" | "locked" {
  if (/vault for this login is locked/i.test(message)) return "locked";
  if (
    /HTTP 40[13]\b|forbidden|unauthori[sz]ed|permission|access denied/i.test(
      message,
    )
  ) {
    return "denied";
  }
  if (
    /HTTP 404\b|not found|no such|does not exist|no field|no item/i.test(
      message,
    )
  ) {
    return "not_found";
  }
  return "connection";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

const UNLOCK_LIMIT = 10;
const UNLOCK_WINDOW_MS = 15 * 60_000;

/** The unlock form's body, or null when it is incomplete. */
function unlockInput(body: unknown): UnlockInput | null {
  const b = (body ?? {}) as Record<string, unknown>;
  const password = typeof b.password === "string" ? b.password : "";
  if (!password) return null;
  if (b.method === "password" && isNonEmptyString(b.email)) {
    const code = typeof b.twoFactorCode === "string" ? b.twoFactorCode : "";
    const provider = Number(b.twoFactorProvider);
    return {
      method: "password",
      email: b.email,
      password,
      ...(code.trim() && Number.isInteger(provider)
        ? { twoFactor: { provider, code: code.trim() } }
        : {}),
    };
  }
  if (
    b.method === "apikey" &&
    isNonEmptyString(b.clientId) &&
    isNonEmptyString(b.clientSecret)
  ) {
    return {
      method: "apikey",
      clientId: b.clientId,
      clientSecret: b.clientSecret,
      password,
    };
  }
  if (b.method === "sso" && isNonEmptyString(b.redirect)) {
    return { method: "sso", redirect: b.redirect, password };
  }
  return null;
}

export function registerSecretSourceRoutes(
  router: Router,
  deps: SourceDeps,
  repository: SecretSourceRepository,
): void {
  const { ctx, tokenStore, sessions } = deps;
  const failures = new Map<string, number[]>();
  const isAdmin = () => ctx.rbac.has("admin.plugins.manage");
  // Secret sources are credentials, so they follow core's credential
  // permissions. ctx.rbac.require only takes this plugin's own names.
  const requireCredentials =
    (action: "view" | "create" | "edit" | "delete") =>
    (req: Request, res: Response, next: () => void) => {
      ctx.rbac
        .has(`credentials.${action}`)
        .then((allowed) => {
          if (allowed) next();
          else {
            res.status(403).json({
              error: "Insufficient permissions",
              required: `credentials.${action}`,
            });
          }
        })
        .catch((error) => {
          ctx.log.error("Failed to check credential permissions", error);
          res.status(500).json({ error: "Failed to check permissions" });
        });
    };
  const allowedPrivateHosts = async () =>
    parseAllowlist(await ctx.settings.get<string>("privateEndpoints"));

  /**
   * @openapi
   * /plugin-api/secret-sources:
   *   get:
   *     summary: List secret sources visible to the caller (own + shared)
   *     tags:
   *       - Secret Sources
   *     responses:
   *       200:
   *         description: The result.
   */
  router.get(
    "/",
    requireCredentials("view") as never,
    async (req: Request, res: Response) => {
      const userId = ctx.currentActor()!;
      try {
        const rows = await repository.listVisibleToUser(userId);
        res.json({
          sources: rows.map((row) => ({
            ...row,
            owned: row.userId === userId,
          })),
        });
      } catch (error) {
        ctx.log.error("Failed to list secret sources", error);
        res.status(500).json({ error: "Failed to list secret sources" });
      }
    },
  );

  /**
   * @openapi
   * /plugin-api/secret-sources:
   *   post:
   *     summary: Create a secret source
   *     description: >
   *       kind is onepassword-connect, infisical, bitwarden-sm,
   *       hashicorp-vault or bitwarden-cli. Sharing a source with every user
   *       requires admin. The token (JSON for kinds with several fields) is
   *       stored encrypted on the server and never returned.
   *     tags:
   *       - Secret Sources
   *     responses:
   *       200:
   *         description: Done.
   */
  router.post(
    "/",
    requireCredentials("create") as never,
    async (req: Request, res: Response) => {
      const userId = ctx.currentActor()!;
      const {
        name,
        kind = "onepassword-connect",
        baseUrl,
        token,
        shared,
      } = req.body ?? {};
      const url = validBaseUrl(baseUrl);
      const provider =
        typeof kind === "string" ? providerForKind(kind) : undefined;
      if (!provider || !KINDS.includes(kind)) {
        return res
          .status(400)
          .json({ error: "Unsupported secret source kind" });
      }
      if (
        !isNonEmptyString(name) ||
        !url ||
        (provider.needsCredential && !isNonEmptyString(token))
      ) {
        return res.status(400).json({
          error: "name, a valid http(s) baseUrl and token are required",
        });
      }
      if (shared === true && !(await isAdmin())) {
        return res
          .status(403)
          .json({ error: "Only admins can share a secret source" });
      }
      try {
        const id = randomUUID();
        const created = await repository.create({
          id,
          userId,
          name: name.trim(),
          kind,
          baseUrl: url,
          shared: shared === true,
        });
        if (isNonEmptyString(token)) await tokenStore.set(id, token.trim());
        await ctx.audit.record({
          action: "secret_source_create",
          resourceType: "secret_source",
          resourceId: created.id,
          resourceName: created.name,
          success: true,
        });
        res.json({ source: { ...created, owned: true } });
      } catch (error) {
        ctx.log.error("Failed to create secret source", error);
        res.status(500).json({ error: "Failed to create secret source" });
      }
    },
  );

  /**
   * @openapi
   * /plugin-api/secret-sources/{id}:
   *   put:
   *     parameters:
   *       - in: path
   *         name: id
   *         required: true
   *         schema:
   *           type: string
   *     summary: Update a secret source (owner only; omit token to keep it)
   *     tags:
   *       - Secret Sources
   *     responses:
   *       200:
   *         description: Done.
   */
  router.put(
    "/:id",
    requireCredentials("edit") as never,
    async (req: Request, res: Response) => {
      const userId = ctx.currentActor()!;
      const { name, baseUrl, token, shared } = req.body ?? {};
      try {
        const source = await repository.findById(String(req.params.id));
        if (!source) {
          return res.status(404).json({ error: "Secret source not found" });
        }
        if (source.userId !== userId) {
          return res
            .status(403)
            .json({ error: "Only the owner can change this source" });
        }
        const url = baseUrl === undefined ? undefined : validBaseUrl(baseUrl);
        if (baseUrl !== undefined && !url) {
          return res.status(400).json({ error: "baseUrl must be http(s)" });
        }
        if (shared === true && !source.shared && !(await isAdmin())) {
          return res
            .status(403)
            .json({ error: "Only admins can share a secret source" });
        }
        await repository.update(source, {
          ...(isNonEmptyString(name) ? { name: name.trim() } : {}),
          ...(url ? { baseUrl: url } : {}),
          ...(typeof shared === "boolean" ? { shared } : {}),
        });
        if (isNonEmptyString(token)) {
          await tokenStore.set(source.id, token.trim());
        }
        if (
          url &&
          url !== source.baseUrl &&
          providerForKind(source.kind)?.perUser
        ) {
          // Sessions belong to the old server.
          await sessions.clearAll(source.id);
        }
        res.json({ success: true });
      } catch (error) {
        ctx.log.error("Failed to update secret source", error);
        res.status(500).json({ error: "Failed to update secret source" });
      }
    },
  );

  /**
   * @openapi
   * /plugin-api/secret-sources/{id}:
   *   delete:
   *     parameters:
   *       - in: path
   *         name: id
   *         required: true
   *         schema:
   *           type: string
   *     summary: Delete a secret source (owner only)
   *     tags:
   *       - Secret Sources
   *     responses:
   *       200:
   *         description: Done.
   */
  router.delete(
    "/:id",
    requireCredentials("delete") as never,
    async (req: Request, res: Response) => {
      const userId = ctx.currentActor()!;
      try {
        const source = await repository.findById(String(req.params.id));
        if (!source) {
          return res.status(404).json({ error: "Secret source not found" });
        }
        if (source.userId !== userId) {
          return res
            .status(403)
            .json({ error: "Only the owner can change this source" });
        }
        await repository.deleteById(source.id);
        await tokenStore.clear(source.id);
        if (providerForKind(source.kind)?.perUser) {
          await sessions.clearAll(source.id);
        }
        await ctx.audit.record({
          action: "secret_source_delete",
          resourceType: "secret_source",
          resourceId: source.id,
          resourceName: source.name,
          success: true,
        });
        res.json({ success: true });
      } catch (error) {
        ctx.log.error("Failed to delete secret source", error);
        res.status(500).json({ error: "Failed to delete secret source" });
      }
    },
  );

  /**
   * @openapi
   * /plugin-api/secret-sources/test-reference:
   *   post:
   *     summary: Check that a secret reference resolves, without returning the secret
   *     description: Uses the same source a connection would use. Answers 200 with a status of found, invalid, no_source, not_found, denied or connection.
   *     tags:
   *       - Secret Sources
   *     responses:
   *       200:
   *         description: Done.
   */
  router.post(
    "/test-reference",
    requireCredentials("view") as never,
    async (req: Request, res: Response) => {
      const userId = ctx.currentActor()!;
      const reference = req.body?.reference;
      const scheme = isNonEmptyString(reference)
        ? reference.trim().split("://")[0].toLowerCase()
        : "";
      const provider = PROVIDERS.find((entry) => entry.scheme === scheme);
      const ref = provider?.parseReference(String(reference)) ?? null;
      if (!provider || !ref) {
        return res.json({ ok: false, status: "invalid" });
      }
      const source = await pickSecretSource(
        repository,
        userId,
        kindsForScheme(provider.scheme),
      );
      const sourceProvider = source ? providerForKind(source.kind) : undefined;
      if (!source || !sourceProvider) {
        return res.json({ ok: false, status: "no_source" });
      }
      try {
        const target = await providerSourceFor(deps, source, userId);
        if (!target.credential && sourceProvider.needsCredential) {
          return res.json({ ok: false, status: "denied", source: source.name });
        }
        await sourceProvider.resolve(ctx.fetch, target, ref);
        res.json({ ok: true, status: "found", source: source.name });
      } catch (error) {
        const message = errorMessage(error);
        res.json({
          ok: false,
          status: referenceFailure(message),
          source: source.name,
          error: message,
        });
      }
    },
  );

  /**
   * @openapi
   * /plugin-api/secret-sources/{id}/test:
   *   post:
   *     parameters:
   *       - in: path
   *         name: id
   *         required: true
   *         schema:
   *           type: string
   *     summary: Check that the source is reachable and the token is accepted
   *     tags:
   *       - Secret Sources
   *     responses:
   *       200:
   *         description: Done.
   */
  /**
   * @openapi
   * /plugin-api/secret-sources/{id}/items:
   *   get:
   *     summary: Items to pick from a secret source
   *     description: Lists items of a source you own or that is shared with you, as references to fill a username and password. Never returns a secret value. Only some kinds of source can list items.
   *     tags:
   *       - Secret Sources
   *     parameters:
   *       - in: path
   *         name: id
   *         required: true
   *         schema:
   *           type: string
   *       - in: query
   *         name: search
   *         schema:
   *           type: string
   *     responses:
   *       200:
   *         description: The items, at most 100.
   *       400:
   *         description: This kind of source can't list items.
   *       404:
   *         description: No such source.
   *       502:
   *         description: The source could not be reached.
   */
  router.get(
    "/:id/items",
    requireCredentials("view") as never,
    async (req: Request, res: Response) => {
      const userId = ctx.currentActor()!;
      try {
        const source = await repository.findById(String(req.params.id));
        if (!source || (source.userId !== userId && !source.shared)) {
          return res.status(404).json({ error: "Secret source not found" });
        }
        const provider = providerForKind(source.kind);
        if (!provider?.listItems) {
          return res
            .status(400)
            .json({ error: "This kind of source can't list items" });
        }
        const search =
          typeof req.query.search === "string"
            ? req.query.search.slice(0, 200)
            : "";
        const items = await provider.listItems(
          ctx.fetch,
          await providerSourceFor(deps, source, userId),
          search,
        );
        res.json({ items });
      } catch (error) {
        if (error instanceof UnlockRequiredError) {
          return res
            .status(409)
            .json({ error: "Unlock your vault first", locked: true });
        }
        ctx.log.warn(
          `Listing secret source items failed: ${errorMessage(error)}`,
        );
        res.status(502).json({ error: "Could not list the items" });
      }
    },
  );

  router.post(
    "/:id/test",
    requireCredentials("view") as never,
    async (req: Request, res: Response) => {
      const userId = ctx.currentActor()!;
      try {
        const source = await repository.findById(String(req.params.id));
        if (!source || (source.userId !== userId && !source.shared)) {
          return res.status(404).json({ error: "Secret source not found" });
        }
        const provider = providerForKind(source.kind);
        if (!provider) {
          return res
            .status(200)
            .json({ ok: false, error: "Unsupported secret source kind" });
        }
        const target = await providerSourceFor(deps, source, userId);
        if (!target.credential && provider.needsCredential) {
          return res
            .status(200)
            .json({ ok: false, error: "No token stored for this source" });
        }
        const detail = await provider.test(ctx.fetch, target);
        res.json({ ok: true, detail });
      } catch (error) {
        res.status(200).json({ ok: false, error: errorMessage(error) });
      }
    },
  );

  /** A source the caller can see whose users each unlock their own vault. */
  async function perUserSource(req: Request, res: Response) {
    const userId = ctx.currentActor()!;
    const source = await repository.findById(String(req.params.id));
    if (!source || (source.userId !== userId && !source.shared)) {
      res.status(404).json({ error: "Secret source not found" });
      return null;
    }
    if (!providerForKind(source.kind)?.perUser) {
      res.status(400).json({ error: "This source is not unlocked per user" });
      return null;
    }
    const credential =
      (await tokenStore.getForOwner(source.id, source.userId)) ?? "";
    return {
      userId,
      source,
      session: { id: source.id, baseUrl: source.baseUrl, credential },
    };
  }

  /**
   * @openapi
   * /plugin-api/secret-sources/{id}/session:
   *   get:
   *     summary: Whether the caller's own vault for this source is unlocked
   *     tags:
   *       - Secret Sources
   *     parameters:
   *       - in: path
   *         name: id
   *         required: true
   *         schema:
   *           type: string
   *     responses:
   *       200:
   *         description: unlocked, the account email, how it was unlocked and when it locks again.
   *       400:
   *         description: This source is not unlocked per user.
   *       404:
   *         description: No such source.
   */
  router.get(
    "/:id/session",
    requireCredentials("view") as never,
    async (req: Request, res: Response) => {
      try {
        const found = await perUserSource(req, res);
        if (!found) return;
        res.json(await sessions.status(found.source.id, found.userId));
      } catch (error) {
        ctx.log.error("Failed to read vault session", error);
        res.status(500).json({ error: "Failed to read the vault session" });
      }
    },
  );

  /**
   * @openapi
   * /plugin-api/secret-sources/{id}/session/sso:
   *   post:
   *     summary: Start an SSO sign in to the caller's own vault
   *     description: Returns the address to open. The sign in ends on a localhost address, which the caller pastes back to the unlock route with their master password.
   *     tags:
   *       - Secret Sources
   *     parameters:
   *       - in: path
   *         name: id
   *         required: true
   *         schema:
   *           type: string
   *     responses:
   *       200:
   *         description: The address to open.
   *       400:
   *         description: This source is not unlocked per user.
   *       404:
   *         description: No such source.
   */
  router.post(
    "/:id/session/sso",
    requireCredentials("view") as never,
    async (req: Request, res: Response) => {
      try {
        const found = await perUserSource(req, res);
        if (!found) return;
        res.json({ url: sessions.startSso(found.session, found.userId) });
      } catch (error) {
        ctx.log.error("Failed to start an SSO sign in", error);
        res.status(500).json({ error: "Failed to start the SSO sign in" });
      }
    },
  );

  /**
   * @openapi
   * /plugin-api/secret-sources/{id}/session:
   *   post:
   *     summary: Unlock the caller's own vault for this source
   *     description: >
   *       method is password (email, password, optional twoFactorProvider and
   *       twoFactorCode), apikey (clientId, clientSecret, password) or sso
   *       (redirect, the address the SSO window ended on, and password).
   *       password is always the master password. The vault stays unlocked for
   *       the caller only, until the source's session length runs out.
   *     tags:
   *       - Secret Sources
   *     parameters:
   *       - in: path
   *         name: id
   *         required: true
   *         schema:
   *           type: string
   *     responses:
   *       200:
   *         description: Unlocked.
   *       400:
   *         description: Sign in failed. twoFactor lists the two-step login providers when a code is needed.
   *       404:
   *         description: No such source.
   *       429:
   *         description: Too many failed attempts.
   */
  router.post(
    "/:id/session",
    requireCredentials("view") as never,
    async (req: Request, res: Response) => {
      let found: Awaited<ReturnType<typeof perUserSource>>;
      try {
        found = await perUserSource(req, res);
      } catch (error) {
        ctx.log.error("Failed to unlock the vault", error);
        return res.status(500).json({ error: "Failed to unlock the vault" });
      }
      if (!found) return;
      const input = unlockInput(req.body);
      if (!input) {
        return res.status(400).json({ error: "Fill in every field" });
      }
      const key = `${found.source.id}:${found.userId}`;
      const now = Date.now();
      const recent = (failures.get(key) ?? []).filter(
        (at) => at > now - UNLOCK_WINDOW_MS,
      );
      if (recent.length >= UNLOCK_LIMIT) {
        return res
          .status(429)
          .json({ error: "Too many failed attempts. Try again later" });
      }
      const audit = (success: boolean) =>
        ctx.audit.record({
          action: "secret_source_unlock",
          resourceType: "secret_source",
          resourceId: found.source.id,
          resourceName: found.source.name,
          success,
        });
      try {
        const status = await sessions.unlock(
          found.session,
          found.userId,
          {
            baseUrl: found.source.baseUrl,
            allowedPrivateHosts: await allowedPrivateHosts(),
          },
          input,
        );
        failures.delete(key);
        await audit(true);
        res.json(status);
      } catch (error) {
        const message = errorMessage(error);
        const known =
          error instanceof VaultLoginError ||
          /master password|key derivation|asked for|too weak/i.test(message);
        const twoFactor =
          error instanceof VaultLoginError ? error.twoFactor : null;
        if (!known) ctx.log.warn(`Vault unlock failed: ${message}`);
        // Asking for a code is not a wrong guess.
        if (!twoFactor) failures.set(key, [...recent, now]);
        await audit(false);
        res.status(400).json({
          error: known ? message : "Could not reach the server",
          ...(twoFactor ? { twoFactor } : {}),
        });
      }
    },
  );

  /**
   * @openapi
   * /plugin-api/secret-sources/{id}/session:
   *   delete:
   *     summary: Lock the caller's own vault for this source
   *     tags:
   *       - Secret Sources
   *     parameters:
   *       - in: path
   *         name: id
   *         required: true
   *         schema:
   *           type: string
   *     responses:
   *       200:
   *         description: Locked.
   *       400:
   *         description: This source is not unlocked per user.
   *       404:
   *         description: No such source.
   */
  router.delete(
    "/:id/session",
    requireCredentials("view") as never,
    async (req: Request, res: Response) => {
      try {
        const found = await perUserSource(req, res);
        if (!found) return;
        await sessions.clear(found.source.id, found.userId);
        res.json({ success: true });
      } catch (error) {
        ctx.log.error("Failed to lock the vault", error);
        res.status(500).json({ error: "Failed to lock the vault" });
      }
    },
  );
}
