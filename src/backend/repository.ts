import { eq, or, sql } from "drizzle-orm";
import type { PluginDatabase } from "@termix-ssh/plugin-sdk/backend";

type SecretSourceKind = "onepassword-connect";

export interface SecretSourceRecord {
  id: string;
  userId: string;
  name: string;
  kind: SecretSourceKind;
  baseUrl: string;
  shared: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface SecretSourceCreateInput {
  id: string;
  userId: string;
  name: string;
  kind: SecretSourceKind;
  baseUrl: string;
  shared: boolean;
}

export interface SecretSourceUpdateInput {
  name?: string;
  baseUrl?: string;
  shared?: boolean;
}

/* eslint-disable @typescript-eslint/no-explicit-any */
// The table comes from ctx.db.define, which the SDK hands back untyped, and
// the drizzle handle is the server's own. Typed at this module's edge instead.
type Table = any;
type Drizzle = any;
/* eslint-enable @typescript-eslint/no-explicit-any */

function isLegacyTokenError(error: unknown): boolean {
  const seen: string[] = [];
  for (let e = error as { message?: string; cause?: unknown } | undefined; e;) {
    if (e.message) seen.push(e.message);
    e = e.cause as typeof e;
  }
  return /token/i.test(seen.join(" "));
}

export type SecretSourceRepository = ReturnType<
  typeof createSecretSourceRepository
>;

/**
 * Per-user secret source storage. The token is never in this table - it
 * lives in ctx.secrets under "source:<id>". A row with an id the caller
 * chose is written without RETURNING so it runs the same on all three
 * engines.
 */
export function createSecretSourceRepository(db: PluginDatabase, table: Table) {
  const client = () => db.client<Drizzle>();

  async function findById(id: string): Promise<SecretSourceRecord | null> {
    const drizzle = await client();
    const rows = await drizzle
      .select()
      .from(table)
      .where(eq(table.id, id))
      .limit(1);
    return (rows[0] as SecretSourceRecord) ?? null;
  }

  return {
    findById,

    async listVisibleToUser(userId: string): Promise<SecretSourceRecord[]> {
      const drizzle = await client();
      return drizzle
        .select()
        .from(table)
        .where(or(eq(table.userId, userId), eq(table.shared, true)));
    },

    async create(
      input: SecretSourceCreateInput,
      now = new Date().toISOString(),
    ): Promise<SecretSourceRecord> {
      const drizzle = await client();
      try {
        await drizzle.insert(table).values({
          id: input.id,
          userId: input.userId,
          name: input.name,
          kind: input.kind,
          baseUrl: input.baseUrl,
          shared: input.shared,
          createdAt: now,
          updatedAt: now,
        });
      } catch (error) {
        if (!isLegacyTokenError(error)) throw error;
        // A database from 2.8 keeps its required token column, since a token
        // there may still be waiting for its owner's key to move it.
        const shared =
          db.dialect === "sqlite" ? Number(input.shared) : input.shared;
        const insert = sql`INSERT INTO ${table} (id, user_id, name, kind, base_url, shared, created_at, updated_at, token) VALUES (${input.id}, ${input.userId}, ${input.name}, ${input.kind}, ${input.baseUrl}, ${shared}, ${now}, ${now}, '')`;
        await (db.dialect === "sqlite"
          ? drizzle.run(insert)
          : drizzle.execute(insert));
      }
      await db.persist();
      return (await findById(input.id)) as SecretSourceRecord;
    },

    async update(
      row: SecretSourceRecord,
      input: SecretSourceUpdateInput,
      now = new Date().toISOString(),
    ): Promise<void> {
      const drizzle = await client();
      await drizzle
        .update(table)
        .set({
          ...(input.name !== undefined ? { name: input.name } : {}),
          ...(input.baseUrl !== undefined ? { baseUrl: input.baseUrl } : {}),
          ...(input.shared !== undefined ? { shared: input.shared } : {}),
          updatedAt: now,
        })
        .where(eq(table.id, row.id));
      await db.persist();
    },

    async deleteById(id: string): Promise<void> {
      const drizzle = await client();
      await drizzle.delete(table).where(eq(table.id, id));
      await db.persist();
    },
  };
}
