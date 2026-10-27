import { appendAudit } from "./audit.js";
import { q, q1 } from "./db/index.js";
import { metrics } from "./telemetry.js";

// ------------------------------------------------------------------ login throttling

/**
 * Sign-in throttling against credential stuffing and brute force: after 5 failures for an
 * account, or 20 from one IP, within 15 minutes, further attempts are refused until the
 * window passes. Counted per instance (Cloud Run runs one in the demo).
 */
const WINDOW_MS = 15 * 60_000;
const failures = new Map<string, number[]>();

function recent(key: string, now: number): number[] {
  const list = (failures.get(key) ?? []).filter((t) => now - t < WINDOW_MS);
  failures.set(key, list);
  return list;
}

export function loginBlocked(email: string, ip: string, now = Date.now()): boolean {
  return recent(`e:${email.toLowerCase()}`, now).length >= 5 || recent(`i:${ip}`, now).length >= 20;
}

export function recordLoginFailure(email: string, ip: string, now = Date.now()): void {
  recent(`e:${email.toLowerCase()}`, now).push(now);
  recent(`i:${ip}`, now).push(now);
  if (failures.size > 100_000) failures.clear();
}

export function clearLoginFailures(email: string): void {
  failures.delete(`e:${email.toLowerCase()}`);
}

// ------------------------------------------------------------------ security audit events

/** Authentication and administration events go into the same hash-chained log as tool calls. */
export async function auditSecurity(e: {
  tenantId?: string | null;
  userId?: string;
  agentId?: string;
  clientId?: string;
  event: string;
  decision: "allow" | "deny";
  reason: string;
  detail?: Record<string, unknown>;
}): Promise<void> {
  if (!e.tenantId) return; // events before a tenant is known (e.g. unknown email) stay in metrics only
  await appendAudit({
    tenantId: e.tenantId,
    userId: e.userId,
    agentId: e.agentId,
    clientId: e.clientId,
    connector: "auth",
    tool: e.event,
    action: "security",
    decision: e.decision,
    reason: e.reason,
    args: e.detail,
  }).catch((err) => console.error("security audit failed", (err as Error).message));
}

// ------------------------------------------------------------------ agent quarantine

/**
 * Detection: an agent that keeps hitting the gateway's rules is behaving like a compromised
 * or confused agent. After QUARANTINE_DENIES denials in QUARANTINE_WINDOW, it is disabled,
 * its tokens are revoked, and the event is written to the audit log for a human to review.
 */
export const QUARANTINE_DENIES = 8;
const QUARANTINE_WINDOW = 10 * 60_000;
const denials = new Map<string, number[]>();

export async function noteDenial(tenantId: string, agentId: string | undefined, code: string, now = Date.now()): Promise<boolean> {
  if (!agentId || code === "rate_limit") return false;
  const list = (denials.get(agentId) ?? []).filter((t) => now - t < QUARANTINE_WINDOW);
  list.push(now);
  denials.set(agentId, list);
  if (list.length < QUARANTINE_DENIES) return false;
  denials.delete(agentId);
  const a = await q1<{ name: string; disabled: boolean }>("SELECT name, disabled FROM agents WHERE tenant_id = $1 AND id = $2", [tenantId, agentId]);
  if (!a || a.disabled) return false;
  await q("UPDATE agents SET disabled = true WHERE tenant_id = $1 AND id = $2", [tenantId, agentId]);
  await q("UPSERT INTO revoked_families (family_id) VALUES ($1)", [agentId]);
  metrics.authEvents.inc({ event: "agent_quarantined" });
  await auditSecurity({
    tenantId,
    agentId,
    event: "agent_quarantined",
    decision: "deny",
    reason: `detection: ${QUARANTINE_DENIES} blocked calls in 10 minutes; agent ${a.name} disabled and its tokens revoked`,
  });
  return true;
}
