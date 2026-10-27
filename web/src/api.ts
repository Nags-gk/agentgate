export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

export async function api<T = unknown>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
  const r = await fetch(`/api${path}`, {
    method: init.method ?? "GET",
    credentials: "same-origin",
    headers: {
      ...(init.body !== undefined ? { "content-type": "application/json" } : {}),
      ...(init.method && init.method !== "GET" ? { "x-agentgate": "1" } : {}),
    },
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new ApiError((data as { error?: string }).error ?? `request failed (${r.status})`, r.status);
  return data as T;
}

export interface Me {
  tenantId: string;
  id: string;
  email: string;
  name: string;
  admin: boolean;
  groups: string[];
  bundles: string[];
}

export interface AuditRow {
  seq: string;
  ts: string;
  user_id: string | null;
  agent_id: string | null;
  client_id: string | null;
  session_id: string | null;
  bundle_id: string | null;
  connector: string;
  tool: string;
  action: string;
  decision: "allow" | "deny" | "error";
  reason: string;
  args_redacted: Record<string, unknown> | null;
  findings: Array<{ kind: string; rule: string; at: string; sample: string }> | null;
  flow: Record<string, unknown> | null;
  latency_ms: string | null;
  result_bytes: string | null;
  trace_id: string | null;
  prev_hash: string;
  hash: string;
}

export interface CallLog {
  tool: string;
  args: Record<string, unknown>;
  isError: boolean;
  text: string;
  why?: "task" | "attack";
  blocked: boolean;
}

export interface ScenarioResult {
  scenario: string;
  title: string;
  kind: "attack" | "benign";
  mode: "gateway" | "direct";
  agent: string;
  attackSucceeded: boolean | null;
  taskDone: boolean;
  calls: CallLog[];
  writes: Array<{ at: string; system: string; what: string; detail: unknown }>;
  finalText?: string;
  error?: string;
}

export const fmtTime = (s: string) => new Date(s).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
export const ago = (s: string) => {
  const sec = Math.max(1, Math.round((Date.now() - new Date(s).getTime()) / 1000));
  if (sec < 60) return `${sec}s ago`;
  if (sec < 3600) return `${Math.round(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.round(sec / 3600)}h ago`;
  return `${Math.round(sec / 86400)}d ago`;
};
