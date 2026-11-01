import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createTestDb, type TestDb } from "@termix-ssh/plugin-sdk/testing";
import { createSecretSourceRepository } from "../../src/backend/repository.js";
import { sources } from "../../src/backend/tables.js";
import { pluginDir } from "./helpers.js";

let db: TestDb;

beforeEach(async () => {
  db = await createTestDb(pluginDir);
  db.sqlite.exec("INSERT INTO users (id) VALUES ('user-1')");
});
afterEach(() => db?.close());

describe("a database upgraded from 2.8", () => {
  it("saves a new source even with the old required token column", async () => {
    db.sqlite.exec(`
      DROP TABLE p_secret_sources_sources;
      CREATE TABLE p_secret_sources_sources (
        id text PRIMARY KEY NOT NULL,
        user_id text NOT NULL,
        name text NOT NULL,
        kind text NOT NULL DEFAULT 'onepassword-connect',
        base_url text NOT NULL,
        token text NOT NULL,
        shared integer NOT NULL DEFAULT 0,
        created_at text NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at text NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
    `);
    const table = await db.database.define(sources);
    const repository = createSecretSourceRepository(db.database, table);
    const saved = await repository.create({
      id: "a",
      userId: "user-1",
      name: "Infisical",
      kind: "onepassword-connect",
      baseUrl: "https://example.com",
      shared: true,
    });
    expect(saved).toMatchObject({ id: "a", name: "Infisical", shared: true });
  });
});
