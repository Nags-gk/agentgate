import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { db, closeDb } from "./index.js";

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), "migrations");

/** Apply each migration file once, in name order, recording it in schema_migrations. */
export async function migrate(log = true): Promise<string[]> {
  await db().query(
    "CREATE TABLE IF NOT EXISTS schema_migrations (name STRING PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())",
  );
  const done = new Set((await db().query("SELECT name FROM schema_migrations")).rows.map((r) => r.name));
  const applied: string[] = [];
  for (const file of (await readdir(dir)).filter((f) => f.endsWith(".sql")).sort()) {
    if (done.has(file)) continue;
    const sql = await readFile(path.join(dir, file), "utf8");
    // CockroachDB does not allow schema changes mixed with other statements in an explicit
    // transaction, so statements run one at a time (each is idempotent).
    for (const stmt of splitSql(sql)) await db().query(stmt);
    await db().query("INSERT INTO schema_migrations (name) VALUES ($1)", [file]);
    applied.push(file);
    if (log) console.log(`migrated ${file}`);
  }
  return applied;
}

function splitSql(sql: string): string[] {
  return sql
    .split("\n")
    .filter((l) => !l.trim().startsWith("--"))
    .join("\n")
    .split(/;\s*(?:\n|$)/)
    .map((s) => s.trim())
    .filter(Boolean);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  migrate()
    .then(() => closeDb())
    .catch((e) => {
      console.error(e);
      process.exit(1);
    });
}
