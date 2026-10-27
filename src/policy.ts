import { LEVELS, levelOf, type ToolDef } from "./connectors/types.js";

/**
 * Least-privilege policy.
 *
 * A bundle is a virtual MCP server: a list of rules naming tools (globs), the resources
 * they may touch (globs over "connector:resource"), and optional argument limits.
 *
 * Two bundles decide every call:
 *   ceiling = union of the bundles the user's groups may use (what the human may do)
 *   grant   = the one bundle this token was issued for (what this agent should do)
 * A call passes only if BOTH allow it. An agent can never exceed its human, and a token
 * leaked from one agent is limited to that agent's job, not the user's full access.
 */

export interface ArgLimit {
  in?: Array<string | number>;
  maxLength?: number;
}
export interface Rule {
  tools: string[];
  resources?: string[];
  args?: Record<string, ArgLimit>;
}
export interface Bundle {
  id: string;
  name: string;
  description: string;
  rules: Rule[];
}

export const glob = (pattern: string, value: string): boolean => {
  const re = new RegExp("^" + pattern.split("*").map((p) => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*") + "$", "i");
  return re.test(value);
};

export interface RuleCheck {
  allowed: boolean;
  reason: string;
}

function checkRule(rule: Rule, tool: string, resource: string | undefined, args: Record<string, unknown>): RuleCheck {
  if (!rule.tools.some((t) => glob(t, tool))) return { allowed: false, reason: "tool not in rule" };
  if (rule.resources?.length) {
    if (!resource) return { allowed: false, reason: "rule is scoped to resources but the call names none" };
    if (!rule.resources.some((r) => glob(r, resource))) return { allowed: false, reason: `${resource} is outside ${rule.resources.join(", ")}` };
  }
  for (const [k, lim] of Object.entries(rule.args ?? {})) {
    const v = args[k];
    if (lim.in && !lim.in.includes(v as string | number)) return { allowed: false, reason: `argument ${k}=${JSON.stringify(v)} is not allowed` };
    if (lim.maxLength !== undefined && typeof v === "string" && v.length > lim.maxLength)
      return { allowed: false, reason: `argument ${k} exceeds ${lim.maxLength} characters` };
  }
  return { allowed: true, reason: "ok" };
}

export function bundleAllows(b: Bundle, tool: string, resource: string | undefined, args: Record<string, unknown>): RuleCheck {
  let last: RuleCheck = { allowed: false, reason: `${tool} is not in bundle ${b.id}` };
  for (const rule of b.rules) {
    const r = checkRule(rule, tool, resource, args);
    if (r.allowed) return r;
    if (r.reason !== "tool not in rule") last = { allowed: false, reason: `${r.reason} (bundle ${b.id})` };
  }
  return last;
}

export const bundleMentions = (b: Bundle, tool: string) => b.rules.some((r) => r.tools.some((t) => glob(t, tool)));

export interface Principal {
  tenantId: string;
  userId: string;
  agentId?: string;
  clientId: string;
  ceiling: Bundle[];
  grant: Bundle;
}

export interface Decision {
  allowed: boolean;
  /** policy | flow | untrusted | secret | rate_limit | ok */
  code: string;
  reason: string;
}

export function authorize(p: Principal, tool: string, resource: string | undefined, args: Record<string, unknown>): Decision {
  const ceilingHits = p.ceiling.map((b) => bundleAllows(b, tool, resource, args));
  if (!ceilingHits.some((h) => h.allowed)) {
    const why = ceilingHits.find((h) => !h.reason.includes("is not in bundle"))?.reason ?? `the user's role does not include ${tool}`;
    return { allowed: false, code: "policy", reason: why };
  }
  const g = bundleAllows(p.grant, tool, resource, args);
  if (!g.allowed) return { allowed: false, code: "policy", reason: g.reason };
  return { allowed: true, code: "ok", reason: "allowed" };
}

export const visibleTools = (p: Principal, tools: ToolDef[]) =>
  tools.filter((t) => bundleMentions(p.grant, t.name) && p.ceiling.some((b) => bundleMentions(b, t.name)));

// ------------------------------------------------------------------ data flow

/** Resource classification from tenant settings: {"slack:#ext-*": "public", ...}. Longest match wins. */
export function classify(labels: Record<string, string>, resource: string | undefined): number {
  if (!resource) return levelOf("internal");
  let best: [number, number] | undefined;
  for (const [pattern, level] of Object.entries(labels)) {
    if (glob(pattern, resource) && (!best || pattern.length > best[0])) best = [pattern.length, levelOf(level)];
  }
  return best ? best[1] : levelOf("internal");
}

export interface SessionState {
  level: number;
  sources: string[];
  untrusted: string[];
}

/**
 * Information-flow control for writes:
 *  - no write down: once a session has read data at level L, it cannot write to a
 *    destination classified below L (confidential incident notes cannot go to a public channel);
 *  - untrusted input cannot reach outside: after a session reads text flagged as a prompt
 *    injection, high-risk tools are refused and writes to public/external destinations are
 *    allowed only back to the resource the text came from (e.g. replying on that issue).
 */
export function checkFlow(tool: ToolDef, resource: string | undefined, labels: Record<string, string>, s: SessionState): Decision {
  if (tool.action !== "write") return { allowed: true, code: "ok", reason: "read" };
  const sink = classify(labels, resource);
  if (s.level > sink) {
    return {
      allowed: false,
      code: "flow",
      reason: `this session has read ${LEVELS[s.level]} data; ${resource ?? "the destination"} is classified ${LEVELS[sink]}`,
    };
  }
  if (s.untrusted.length) {
    if (tool.risk === "high") return { allowed: false, code: "untrusted", reason: `high-risk tool after reading flagged content from ${s.untrusted.join(", ")}` };
    // Flagged content may still steer internal work (file a ticket, post in #eng: logged and
    // reviewable), but it may not push anything outside the company unless the destination
    // is the place the content came from (e.g. replying on the same public issue).
    if (sink === 0 && (!resource || !s.untrusted.includes(resource)))
      return {
        allowed: false,
        code: "untrusted",
        reason: `after reading flagged content from ${s.untrusted.join(", ")}, writes to public or external destinations are blocked`,
      };
  }
  return { allowed: true, code: "ok", reason: "flow ok" };
}
