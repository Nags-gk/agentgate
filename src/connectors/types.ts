/** Data sensitivity, ordered. A session's level is the highest level it has read. */
export const LEVELS = ["public", "internal", "confidential", "restricted"] as const;
export type LevelName = (typeof LEVELS)[number];
export const levelOf = (name: string): number => {
  const i = LEVELS.indexOf(name as LevelName);
  return i < 0 ? 1 : i;
};

export type JsonSchema = { type: "object"; properties: Record<string, unknown>; required?: string[] };

export interface ToolDef {
  /** Gateway-wide name, prefixed by connector: github_list_issues. */
  name: string;
  title: string;
  description: string;
  inputSchema: JsonSchema;
  /** Reads never move data out; writes are checked against data-flow rules. */
  action: "read" | "write";
  /** high = destructive or hard to undo. */
  risk: "low" | "medium" | "high";
}

export interface CallContext {
  /** Upstream credential, decrypted by the gateway for this call only. Never sent to the agent. */
  credential?: string;
  signal: AbortSignal;
  /** Base URL of the upstream API (real service or the built-in simulator). */
  baseUrl: string;
}

export interface CallResult {
  /** JSON-serializable result returned to the agent as text. */
  data: unknown;
}

export interface Connector {
  id: string;
  name: string;
  description: string;
  tools: ToolDef[];
  /** Resource a call touches, used for constraints and classification: "github:acme/payments". */
  resource(tool: string, args: Record<string, unknown>): string | undefined;
  call(tool: string, args: Record<string, unknown>, ctx: CallContext): Promise<CallResult>;
  /** The permissions a raw upstream token for this connector usually carries (for blast radius). */
  directTokenScopes: string[];
}

export class UpstreamError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
  }
}

/** Small fetch wrapper: JSON in/out, auth header, typed errors, abort support. */
export async function http(
  ctx: CallContext,
  method: string,
  path: string,
  opts: { body?: unknown; headers?: Record<string, string>; auth?: (cred: string) => Record<string, string> } = {},
): Promise<unknown> {
  if (!ctx.credential) throw new UpstreamError("no credential stored for this connector", 401);
  const headers: Record<string, string> = {
    accept: "application/json",
    "user-agent": "agentgate/0.1",
    ...(opts.auth ? opts.auth(ctx.credential) : { authorization: `Bearer ${ctx.credential}` }),
    ...opts.headers,
  };
  if (opts.body !== undefined) headers["content-type"] = "application/json";
  const res = await fetch(ctx.baseUrl + path, {
    method,
    headers,
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
    signal: ctx.signal,
  });
  const text = await res.text();
  let parsed: unknown = text;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    /* non-JSON body */
  }
  if (!res.ok) {
    const msg = (parsed as { message?: string; error?: string })?.message ?? (parsed as { error?: string })?.error;
    throw new UpstreamError(`${method} ${path} -> ${res.status}${msg ? `: ${msg}` : ""}`, res.status);
  }
  return parsed;
}

export const str = (args: Record<string, unknown>, k: string): string => {
  const v = args[k];
  if (typeof v !== "string" || !v) throw new UpstreamError(`argument '${k}' must be a non-empty string`, 400);
  return v;
};
