import { randomUUID } from "node:crypto";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import type { Context } from "hono";
import { config } from "../config.js";
import { OAuthError, verifyAccessToken, type AccessClaims } from "../auth/tokens.js";
import { getBundleCached, getUserCached, userBundlesCached } from "../principals.js";
import type { Principal } from "../policy.js";
import { visibleTools } from "../policy.js";
import { metrics } from "../telemetry.js";
import { callTool, ensureSession } from "./pipeline.js";
import { allTools } from "./registry.js";

/**
 * The MCP endpoint (Streamable HTTP). Each authenticated client session gets its own MCP
 * server instance whose tool list is the caller's effective permissions. A session is bound
 * to the identity that created it; a different token cannot drive someone else's session.
 */

interface Live {
  transport: WebStandardStreamableHTTPServerTransport;
  owner: string;
  lastUsed: number;
}
const sessions = new Map<string, Live>();
const SESSION_IDLE_MS = 30 * 60_000;

setInterval(() => {
  const now = Date.now();
  for (const [id, s] of sessions) if (now - s.lastUsed > SESSION_IDLE_MS) void s.transport.close().finally(() => sessions.delete(id));
}, 60_000).unref();

const ownerKey = (c: AccessClaims) => `${c.tid}|${c.sub}|${c.cid}|${c.bid}|${c.agt ?? ""}`;

export async function principalFor(c: AccessClaims): Promise<Principal> {
  const user = await getUserCached(c.tid, c.sub!);
  if (!user) throw new OAuthError("invalid_token", "user no longer exists", 401);
  const grant = await getBundleCached(c.tid, c.bid);
  if (!grant) throw new OAuthError("invalid_token", "the bundle this token was granted for no longer exists", 401);
  return { tenantId: c.tid, userId: user.id, agentId: c.agt, clientId: c.cid, ceiling: await userBundlesCached(c.tid, user.groups), grant };
}

function buildServer(claims: AccessClaims, sessionRef: { id?: string }): Server {
  const server = new Server(
    { name: "agentgate", version: "0.1.0", title: "AgentGate" },
    {
      capabilities: { tools: { listChanged: false } },
      instructions:
        "Tools here are scoped to what this agent is allowed to do. Calls are logged. If a call is blocked, the error explains why; do not retry it with a different tool to get around the rule.",
    },
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    // Policy is re-read on every listing, so an admin's change applies without reconnecting.
    const p = await principalFor(claims);
    return {
      tools: visibleTools(p, allTools()).map((t) => ({
        name: t.name,
        title: t.title,
        description: t.description,
        inputSchema: t.inputSchema,
        annotations: {
          readOnlyHint: t.action === "read",
          destructiveHint: t.risk === "high",
          openWorldHint: true,
        },
      })),
    };
  });
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const p = await principalFor(claims);
    const sessionId = sessionRef.id ?? `stateless-${randomUUID()}`;
    await ensureSession(p, sessionId, p.grant.id);
    const out = await callTool(p, sessionId, req.params.name, req.params.arguments ?? {});
    return { content: [{ type: "text", text: out.text }], isError: out.isError };
  });
  return server;
}

function unauthorized(c: Context, e: OAuthError | Error) {
  const desc = e instanceof OAuthError ? e.description : "invalid token";
  c.header(
    "WWW-Authenticate",
    `Bearer resource_metadata="${config.publicUrl}/.well-known/oauth-protected-resource/mcp", error="invalid_token", error_description="${desc.replace(/"/g, "'")}"`,
  );
  return c.json({ error: "invalid_token", error_description: desc }, 401);
}

export async function handleMcp(c: Context): Promise<Response> {
  const auth = c.req.header("authorization");
  if (!auth?.startsWith("Bearer ")) {
    c.header("WWW-Authenticate", `Bearer resource_metadata="${config.publicUrl}/.well-known/oauth-protected-resource/mcp"`);
    return c.json({ error: "unauthorized", error_description: "Bearer token required" }, 401);
  }
  let claims: AccessClaims;
  try {
    claims = await verifyAccessToken(auth.slice(7));
  } catch (e) {
    metrics.authEvents.inc({ event: "token_rejected" });
    return unauthorized(c, e as Error);
  }

  const sid = c.req.header("mcp-session-id");
  if (sid) {
    const live = sessions.get(sid);
    if (!live) return c.json({ jsonrpc: "2.0", error: { code: -32001, message: "Session not found" }, id: null }, 404);
    if (live.owner !== ownerKey(claims)) return c.json({ jsonrpc: "2.0", error: { code: -32003, message: "Session belongs to another principal" }, id: null }, 403);
    live.lastUsed = Date.now();
    return live.transport.handleRequest(c.req.raw);
  }

  if (c.req.method !== "POST") return c.json({ jsonrpc: "2.0", error: { code: -32000, message: "Missing session; send initialize first" }, id: null }, 400);

  const ref: { id?: string } = {};
  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
    enableJsonResponse: true,
    onsessioninitialized: (id) => {
      ref.id = id;
      sessions.set(id, { transport, owner: ownerKey(claims), lastUsed: Date.now() });
    },
    onsessionclosed: (id) => {
      sessions.delete(id);
    },
  });
  const server = buildServer(claims, ref);
  await server.connect(transport);
  return transport.handleRequest(c.req.raw);
}

export const liveSessionCount = () => sessions.size;
