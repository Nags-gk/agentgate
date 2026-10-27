import pg from "pg";
import { config } from "../config.js";
import { metrics } from "../telemetry.js";

const { Pool } = pg;

export type Db = pg.Pool;
export type Tx = pg.PoolClient;

let pool: pg.Pool | undefined;

export function db(): pg.Pool {
  if (!pool) {
    pool = new Pool({
      connectionString: config.databaseUrl,
      max: config.dbPoolSize,
      idleTimeoutMillis: 30_000,
      // CockroachDB Cloud requires TLS; the connection string carries sslmode.
    });
    pool.on("error", (err) => console.error("pg pool error", err.message));
  }
  return pool;
}

export async function closeDb(): Promise<void> {
  await pool?.end();
  pool = undefined;
}

/** SQLSTATE 40001: CockroachDB aborted a SERIALIZABLE transaction that must be retried. */
export function isRetryable(err: unknown): boolean {
  const code = (err as { code?: string })?.code;
  return code === "40001" || code === "40003";
}

/**
 * Run `fn` in a SERIALIZABLE transaction, retrying with jittered exponential backoff when
 * CockroachDB reports a retryable conflict. This is the client-side retry loop the
 * CockroachDB docs require for contended writes (the audit-chain head is one).
 */
export async function withTx<T>(fn: (tx: Tx) => Promise<T>, maxAttempts = 8): Promise<T> {
  const client = await db().connect();
  try {
    for (let attempt = 1; ; attempt++) {
      try {
        await client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
        const out = await fn(client);
        await client.query("COMMIT");
        return out;
      } catch (err) {
        await client.query("ROLLBACK").catch(() => {});
        if (!isRetryable(err) || attempt >= maxAttempts) throw err;
        metrics.txRetries.inc();
        const backoff = Math.min(1000, 2 ** attempt * 5) * (0.5 + Math.random());
        await new Promise((r) => setTimeout(r, backoff));
      }
    }
  } finally {
    client.release();
  }
}

export async function q<T extends pg.QueryResultRow = pg.QueryResultRow>(
  sql: string,
  params: unknown[] = [],
  tx?: Tx,
): Promise<T[]> {
  const res = await (tx ?? db()).query<T>(sql, params);
  return res.rows;
}

export async function q1<T extends pg.QueryResultRow = pg.QueryResultRow>(
  sql: string,
  params: unknown[] = [],
  tx?: Tx,
): Promise<T | undefined> {
  return (await q<T>(sql, params, tx))[0];
}
