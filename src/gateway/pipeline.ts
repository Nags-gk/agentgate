import { trace } from "@opentelemetry/api";
import { appendAudit } from "../audit.js";
import { config } from "../config.js";
import { q1, q } from "../db/index.js";
import { LEVELS, UpstreamError, type ToolDef } from "../connectors/types.js";
import { INJECTION_NOTICE, findInjections, redactSecrets, secretsInArgs, type Finding } from "../guard/scan.js";
import { authorize, checkFlow, classify, type Decision, type Principal, type SessionState } from "../policy.js";
import { tenantLabels } from "../principals.js";
import { metrics, withSpan } from "../telemetry.js";
import { RateLimiter } from "./ratelimit.js";
import { allTools, baseUrlFor, connectorFor, credentialFor } from "./registry.js";
import { noteDenial } from "../security.js";

export const limiter = new RateLimiter(config.rateLimitPerMin);

export interface CallOutcome {
  isError: boolean;
  text: string;
  decision: Decision;
  findings: Finding[];
}

/** One queue per MCP session: calls run in order so data-flow state is never read stale. */
const queues = new Map<string, Promise<unknown>>();
function serialize<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const prev = queues.get(key) ?? Promise.resolve();
  const next = prev.catch(() => {}).then(fn);
  queues.set(key, next);
  next.finally(() => {
    if (queues.get(key) === next) queues.delete(key);
  });
  return next;
}

// Session labels are kept in memory for sessions this instance is serving (their calls are
// serialized here, so memory is authoritative) and written through to CockroachDB.
const sessionState = new Map<string, SessionState>();

export async function loadSession(tenantId: string, sessionId: string): Promise<SessionState> {
  const key = `${tenantId}:${sessionId}`;
  const hit = sessionState.get(key);
  if (hit) return hit;
  const r = await q1<{ level: string; sources: string[]; untrusted: string[] }>(
    "SELECT level, sources, untrusted FROM mcp_sessions WHERE tenant_id = $1 AND id = $2",
    [tenantId, sessionId],
  );
  const s = { level: r ? Number(r.level) : 0, sources: r?.sources ?? [], untrusted: r?.untrusted ?? [] };
  if (sessionState.size > 50_000) sessionState.clear();
  sessionState.set(key, s);
  return s;
}

const knownSessions = new Set<string>();
export async function ensureSession(p: Principal, sessionId: string, bundleId: string): Promise<void> {
  const key = `${p.tenantId}:${sessionId}`;
  if (knownSessions.has(key)) return;
  if (knownSessions.size > 50_000) knownSessions.clear();
  knownSessions.add(key);
  await q(
    `INSERT INTO mcp_sessions (tenant_id, id, user_id, agent_id, client_id, bundle_id) VALUES ($1,$2,$3,$4,$5,$6)
     ON CONFLICT (tenant_id, id) DO UPDATE SET last_seen = now()`,
    [p.tenantId, sessionId, p.userId, p.agentId ?? null, p.clientId, bundleId],
  );
}

/** Raise the session's level and record the source in one statement (calls in a session are already serialized). */
async function recordRead(tenantId: string, sessionId: string, level: number, resource: string | undefined, untrusted: boolean) {
  const s = await loadSession(tenantId, sessionId);
  s.level = Math.max(s.level, level);
  if (resource && !s.sources.includes(resource)) s.sources.push(resource);
  if (untrusted && resource && !s.untrusted.includes(resource)) s.untrusted.push(resource);
  await q(
    `UPDATE mcp_sessions SET
       level = GREATEST(level, $3),
       sources = CASE WHEN $4::STRING IS NULL OR $4 = ANY(sources) THEN sources ELSE array_append(sources, $4) END,
       untrusted = CASE WHEN $5 AND $4::STRING IS NOT NULL AND NOT ($4 = ANY(untrusted)) THEN array_append(untrusted, $4) ELSE untrusted END,
       last_seen = now()
     WHERE tenant_id = $1 AND id = $2`,
    [tenantId, sessionId, level, resource ?? null, untrusted],
  );
}

function deny(code: string, reason: string): Decision {
  return { allowed: false, code, reason };
}

/**
 * The gateway's request path for one tool call:
 *   rate limit -> policy (ceiling AND grant) -> secrets in write args -> data-flow rules
 *   -> decrypt credential -> upstream call (timeout) -> redact secrets -> flag injections
 *   -> update session labels -> hash-chained audit event.
 */
export async function callTool(p: Principal, sessionId: string, toolName: string, rawArgs: unknown): Promise<CallOutcome> {
  return serialize(`${p.tenantId}:${sessionId}`, () =>
    withSpan("gateway.tool_call", { tool: toolName, tenant: p.tenantId, agent: p.agentId, bundle: p.grant.id }, async (span) => {
      const started = performance.now();
      const args = rawArgs && typeof rawArgs === "object" && !Array.isArray(rawArgs) ? (rawArgs as Record<string, unknown>) : {};
      const connector = connectorFor(toolName);
      const tool: ToolDef | undefined = allTools().find((t) => t.name === toolName);
      const resource = connector?.resource(toolName, args);
      const labels = await tenantLabels(p.tenantId);
      const findings: Finding[] = [];
      let decision: Decision;
      let text = "";
      let resultBytes = 0;
      let flow: Record<string, unknown> | undefined;
      let sessionWrite: Promise<void> = Promise.resolve();

      const policyStart = performance.now();
      if (!connector || !tool) decision = deny("policy", `unknown tool ${toolName}`);
      else if (!limiter.take(p.agentId ?? `${p.clientId}:${p.userId}`)) {
        metrics.rateLimited.inc();
        decision = deny("rate_limit", `rate limit of ${config.rateLimitPerMin} calls per minute exceeded`);
      } else {
        decision = authorize(p, toolName, resource, args);
        if (decision.allowed && tool.action === "write") {
          const leaked = secretsInArgs(args);
          if (leaked.length) {
            findings.push(...leaked);
            decision = deny("secret", `arguments contain credentials (${[...new Set(leaked.map((f) => f.rule))].join(", ")}); blocked to prevent exfiltration`);
          }
        }
        if (decision.allowed) {
          const s = await loadSession(p.tenantId, sessionId);
          decision = checkFlow(tool, resource, labels, s);
          flow = { session_level: LEVELS[s.level], sink_level: tool.action === "write" ? LEVELS[classify(labels, resource)] : undefined, untrusted: s.untrusted };
        }
      }
      metrics.policyLatency.observe((performance.now() - policyStart) / 1000);

      if (decision.allowed && connector && tool) {
        const ac = new AbortController();
        const timer = setTimeout(() => ac.abort(), config.toolTimeoutMs);
        try {
          const credential = await credentialFor(p.tenantId, p.userId, connector.id);
          const baseUrl = await baseUrlFor(p.tenantId, connector.id);
          const res = await withSpan("upstream.call", { connector: connector.id, tool: toolName }, () =>
            connector.call(toolName, args, { credential, signal: ac.signal, baseUrl }),
          );
          const red = redactSecrets(res.data);
          findings.push(...red.findings);
          const inj = findInjections(red.value);
          findings.push(...inj);
          text = JSON.stringify(red.value, null, 1);
          if (inj.length) text = `${INJECTION_NOTICE}\n${text}`;
          resultBytes = Buffer.byteLength(text);
          if (tool.action === "read") {
            const level = classify(labels, resource);
            sessionWrite = recordRead(p.tenantId, sessionId, level, resource, inj.length > 0);
            flow = { ...flow, read_level: LEVELS[level] };
          }
        } catch (err) {
          const e = err as Error;
          const msg = ac.signal.aborted ? `upstream timed out after ${config.toolTimeoutMs} ms` : e.message;
          decision = { allowed: true, code: "upstream_error", reason: msg };
          text = `Upstream error: ${msg}`;
          span.setAttribute("upstream.status", (err as UpstreamError).status ?? 0);
        } finally {
          clearTimeout(timer);
        }
      }

      for (const f of findings) metrics.guardFindings.inc({ kind: f.kind });
      const outcome: CallOutcome["decision"] = decision;
      const auditDecision = !decision.allowed ? "deny" : decision.code === "upstream_error" ? "error" : "allow";
      metrics.toolCalls.inc({ connector: connector?.id ?? "unknown", tool: toolName, decision: auditDecision });
      const latency = performance.now() - started;
      metrics.toolLatency.observe({ connector: connector?.id ?? "unknown" }, latency / 1000);
      span.setAttribute("decision", auditDecision);
      span.setAttribute("decision.code", decision.code);

      // The session write-through and the audit append are independent; run them together.
      const audited = appendAudit({
        tenantId: p.tenantId,
        userId: p.userId,
        agentId: p.agentId,
        clientId: p.clientId,
        sessionId,
        bundleId: p.grant.id,
        connector: connector?.id ?? "unknown",
        tool: toolName,
        action: tool?.action ?? "unknown",
        decision: auditDecision,
        reason: decision.allowed ? (decision.code === "upstream_error" ? decision.reason : "allowed") : `${decision.code}: ${decision.reason}`,
        args: { ...redactSecrets(args).value as object, ...(resource ? { _resource: resource } : {}) },
        findings: findings.length ? findings : undefined,
        flow,
        latencyMs: Math.round(latency),
        resultBytes,
        traceId: trace.getActiveSpan()?.spanContext().traceId,
      });
      await Promise.all([audited, sessionWrite]);

      if (!decision.allowed) {
        const quarantined = await noteDenial(p.tenantId, p.agentId, decision.code);
        if (quarantined) decision = { ...decision, reason: `${decision.reason}. This agent has now been quarantined after repeated blocked calls.` };
        return {
          isError: true,
          text: `Blocked by AgentGate (${decision.code}): ${decision.reason}`,
          decision: outcome,
          findings,
        };
      }
      return { isError: decision.code === "upstream_error", text, decision: outcome, findings };
    }),
  );
}
