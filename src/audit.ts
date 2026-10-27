import { createHash } from "node:crypto";
import { isRetryable, q } from "./db/index.js";
import { metrics } from "./telemetry.js";

export interface AuditInput {
  tenantId: string;
  userId?: string;
  agentId?: string;
  clientId?: string;
  sessionId?: string;
  bundleId?: string;
  connector: string;
  tool: string;
  action: string;
  decision: "allow" | "deny" | "error";
  reason: string;
  args?: unknown;
  findings?: unknown;
  flow?: unknown;
  latencyMs?: number;
  resultBytes?: number;
  traceId?: string;
}

const GENESIS = "0".repeat(64);

/** Canonical JSON (sorted keys) so the hash does not depend on key order. */
export function canonical(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v ?? null);
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  return `{${Object.keys(v as object)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`)
    .join(",")}}`;
}

export const eventHash = (prev: string, body: Record<string, unknown>) => createHash("sha256").update(prev).update(canonical(body)).digest("hex");

/** What JSONB will give back: undefined keys dropped. Hash exactly what is stored. */
const norm = (v: unknown) => (v === undefined ? null : (JSON.parse(JSON.stringify(v)) as unknown));

function body(e: AuditInput, seq: number, ts: string) {
  return {
    seq,
    ts,
    user_id: e.userId ?? null,
    agent_id: e.agentId ?? null,
    client_id: e.clientId ?? null,
    session_id: e.sessionId ?? null,
    bundle_id: e.bundleId ?? null,
    connector: e.connector,
    tool: e.tool,
    action: e.action,
    decision: e.decision,
    reason: e.reason,
    args_redacted: norm(e.args),
    findings: norm(e.findings),
    flow: norm(e.flow),
  };
}

/**
 * Append an event to the tenant's hash chain, with group commit.
 *
 * The chain tip lives in audit_heads and is read and advanced in a SERIALIZABLE transaction,
 * so writers for one tenant are inherently serialized. Instead of one transaction per event,
 * events that arrive while a commit is in flight are queued and written together in the next
 * transaction (one multi-row INSERT). Callers still wait for their own event to be durable,
 * so a tool result is never returned before its audit record is committed.
 */
interface Pending {
  e: AuditInput;
  resolve: (r: { seq: number; hash: string }) => void;
  reject: (err: unknown) => void;
}
const queues = new Map<string, { pending: Pending[]; running: boolean }>();
const MAX_BATCH = 200;

export function appendAudit(e: AuditInput): Promise<{ seq: number; hash: string }> {
  return new Promise((resolve, reject) => {
    let qu = queues.get(e.tenantId);
    if (!qu) queues.set(e.tenantId, (qu = { pending: [], running: false }));
    qu.pending.push({ e, resolve, reject });
    if (!qu.running) void drain(e.tenantId);
  });
}

async function drain(tenantId: string): Promise<void> {
  const qu = queues.get(tenantId)!;
  qu.running = true;
  try {
    while (qu.pending.length) {
      const batch = qu.pending.splice(0, MAX_BATCH);
      try {
        const out = await commitBatch(tenantId, batch.map((b) => b.e));
        batch.forEach((b, i) => b.resolve(out[i]!));
      } catch (err) {
        batch.forEach((b) => b.reject(err));
      }
    }
  } finally {
    qu.running = false;
  }
}

// Chain tip per tenant, cached: this instance is normally the only writer, so the next append
// can be computed without reading the head first. Another writer advancing the head is
// detected by the conditional UPDATE below, and the cache is reloaded.
const heads = new Map<string, { seq: number; hash: string }>();

async function loadHead(tenantId: string): Promise<{ seq: number; hash: string }> {
  await q("INSERT INTO audit_heads (tenant_id, seq, hash) VALUES ($1, 0, $2) ON CONFLICT (tenant_id) DO NOTHING", [tenantId, GENESIS]);
  const h = (await q<{ seq: string; hash: string }>("SELECT seq, hash FROM audit_heads WHERE tenant_id = $1", [tenantId]))[0]!;
  const head = { seq: Number(h.seq), hash: h.hash };
  heads.set(tenantId, head);
  return head;
}

const CASTS = [
  "UUID", "INT8", "TIMESTAMPTZ", "UUID", "UUID", "STRING", "STRING", "STRING", "STRING", "STRING", "STRING",
  "STRING", "STRING", "JSONB", "JSONB", "JSONB", "INT8", "INT8", "STRING", "STRING", "STRING",
];

/**
 * One round trip per batch: a data-modifying CTE advances the chain head only if it is still
 * where this instance expects (optimistic concurrency), and the INSERT runs only if that
 * UPDATE matched. Both happen in one implicit transaction.
 */
async function commitBatch(tenantId: string, events: AuditInput[]): Promise<Array<{ seq: number; hash: string }>> {
  for (let attempt = 0; attempt < 8; attempt++) {
    const head = heads.get(tenantId) ?? (await loadHead(tenantId));
    let seq = head.seq;
    let prev = head.hash;
    const ts = new Date().toISOString();
    const rows: unknown[][] = [];
    const out: Array<{ seq: number; hash: string }> = [];
    for (const e of events) {
      seq += 1;
      const b = body(e, seq, ts);
      const hash = eventHash(prev, b);
      rows.push([
        tenantId, seq, ts, b.user_id, b.agent_id, b.client_id, b.session_id, b.bundle_id, e.connector, e.tool, e.action,
        e.decision, e.reason, JSON.stringify(b.args_redacted), JSON.stringify(b.findings), JSON.stringify(b.flow),
        e.latencyMs ?? null, e.resultBytes ?? null, e.traceId ?? null, prev, hash,
      ]);
      out.push({ seq, hash });
      prev = hash;
    }
    const base = 4;
    const values = rows
      .map((_, r) => `(${CASTS.map((t, c) => `$${base + r * CASTS.length + c + 1}::${t}`).join(",")})`)
      .join(",");
    try {
      const inserted = await q(
        `WITH upd AS (
           UPDATE audit_heads SET seq = $1, hash = $2 WHERE tenant_id = $3 AND seq = $4 RETURNING tenant_id
         )
         INSERT INTO audit_events (tenant_id, seq, ts, user_id, agent_id, client_id, session_id, bundle_id, connector, tool, action,
           decision, reason, args_redacted, findings, flow, latency_ms, result_bytes, trace_id, prev_hash, hash)
         SELECT * FROM (VALUES ${values}) AS v WHERE EXISTS (SELECT 1 FROM upd)
         RETURNING seq`,
        [seq, prev, tenantId, head.seq, ...rows.flat()],
      );
      if (inserted.length === events.length) {
        heads.set(tenantId, { seq, hash: prev });
        return out;
      }
    } catch (err) {
      if (!isRetryable(err)) throw err;
    }
    // Another writer moved the head (or the transaction was retried): reload and rebuild.
    metrics.txRetries.inc();
    await loadHead(tenantId);
  }
  throw new Error("audit append failed after repeated conflicts");
}

export interface VerifyResult {
  ok: boolean;
  checked: number;
  firstSeq?: number;
  lastSeq?: number;
  brokenAt?: number;
  problem?: string;
}

/**
 * Recompute every hash in order. Retention (row-level TTL) deletes the oldest rows, so the
 * oldest surviving row's prev_hash is taken as the anchor; everything after it must link.
 */
export async function verifyChain(tenantId: string): Promise<VerifyResult> {
  const rows = await q<Record<string, unknown> & { seq: string; prev_hash: string; hash: string; ts: Date }>(
    `SELECT seq, ts, user_id, agent_id, client_id, session_id, bundle_id, connector, tool, action, decision, reason,
            args_redacted, findings, flow, prev_hash, hash
     FROM audit_events WHERE tenant_id = $1 ORDER BY seq`,
    [tenantId],
  );
  let prev: string | undefined;
  let prevSeq: number | undefined;
  for (const r of rows) {
    const seq = Number(r.seq);
    if (prev !== undefined && r.prev_hash !== prev) return { ok: false, checked: rows.length, brokenAt: seq, problem: "prev_hash does not match the previous event" };
    if (prevSeq !== undefined && seq !== prevSeq + 1) return { ok: false, checked: rows.length, brokenAt: seq, problem: `gap after seq ${prevSeq}` };
    const b = {
      seq,
      ts: new Date(r.ts).toISOString(),
      user_id: r.user_id ?? null,
      agent_id: r.agent_id ?? null,
      client_id: r.client_id ?? null,
      session_id: r.session_id ?? null,
      bundle_id: r.bundle_id ?? null,
      connector: r.connector,
      tool: r.tool,
      action: r.action,
      decision: r.decision,
      reason: r.reason,
      args_redacted: r.args_redacted ?? null,
      findings: r.findings ?? null,
      flow: r.flow ?? null,
    };
    if (eventHash(r.prev_hash, b) !== r.hash) return { ok: false, checked: rows.length, brokenAt: seq, problem: "event contents do not match its hash" };
    prev = r.hash;
    prevSeq = seq;
  }
  const head = (await q<{ seq: string; hash: string }>("SELECT seq, hash FROM audit_heads WHERE tenant_id = $1", [tenantId]))[0];
  if (head && prev !== undefined && head.hash !== prev) return { ok: false, checked: rows.length, problem: "chain tip does not match the last event (rows deleted from the end?)" };
  return { ok: true, checked: rows.length, firstSeq: rows.length ? Number(rows[0]!.seq) : undefined, lastSeq: prevSeq };
}
