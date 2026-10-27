import { Hono, type Context, type Next } from "hono";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import { SignJWT, jwtVerify, createLocalJWKSet } from "jose";
import { z } from "zod";
import { config, resourceUrl } from "./config.js";
import { q, q1 } from "./db/index.js";
import { verifyChain } from "./audit.js";
import { jwks, rotateSigningKey, signingKey, verifyPassword } from "./auth/crypto.js";
import { clientIp, createAgentClient } from "./auth/oauth.js";
import { auditSecurity, clearLoginFailures, loginBlocked, recordLoginFailure } from "./security.js";
import { findUserByEmail, getUser, userBundles } from "./principals.js";
import { blastRadius } from "./insights.js";
import { liveSessionCount } from "./gateway/mcp.js";
import { allTools, connectors, credentialAad } from "./gateway/registry.js";
import { runScenario } from "./agents/runner.js";
import { SCENARIOS } from "./agents/scenarios.js";
import { sim } from "./sim/index.js";
import { spanStore } from "./telemetry.js";
import { getVault } from "./vault.js";
import { clearPolicyCaches } from "./cache.js";
import type { Rule } from "./policy.js";

const COOKIE = "ag_session";
type Vars = { user: { tenantId: string; id: string; email: string; name: string; admin: boolean } };

async function sessionToken(u: { tenant_id: string; id: string }) {
  const k = await signingKey();
  return new SignJWT({ tid: u.tenant_id })
    .setProtectedHeader({ alg: "ES256", kid: k.kid, typ: "admin+jwt" })
    .setSubject(u.id)
    .setAudience(`${config.publicUrl}/api`)
    .setIssuedAt()
    .setExpirationTime("8h")
    .sign(k.privateKey);
}

async function requireUser(c: Context<{ Variables: Vars }>, next: Next) {
  const tok = getCookie(c, COOKIE);
  if (!tok) return c.json({ error: "sign in required" }, 401);
  try {
    await signingKey();
    const { payload } = await jwtVerify(tok, createLocalJWKSet(jwks()), { audience: `${config.publicUrl}/api`, typ: "admin+jwt", algorithms: ["ES256"] });
    const u = await getUser(String(payload.tid), String(payload.sub));
    if (!u) return c.json({ error: "sign in required" }, 401);
    c.set("user", { tenantId: u.tenant_id, id: u.id, email: u.email, name: u.display_name, admin: u.is_admin });
  } catch {
    return c.json({ error: "sign in required" }, 401);
  }
  // State-changing requests must carry a custom header: browsers cannot send it cross-site
  // without a CORS preflight, which this API never approves (CSRF defense with SameSite cookies).
  if (c.req.method !== "GET" && c.req.header("x-agentgate") !== "1") return c.json({ error: "missing x-agentgate header" }, 403);
  return next();
}

const requireAdmin = async (c: Context<{ Variables: Vars }>, next: Next) => (c.get("user").admin ? next() : c.json({ error: "admin only" }, 403));

const ruleSchema: z.ZodType<Rule> = z.object({
  tools: z.array(z.string().min(1).max(100)).min(1).max(50),
  resources: z.array(z.string().min(1).max(200)).max(50).optional(),
  args: z.record(z.string(), z.object({ in: z.array(z.union([z.string(), z.number()])).max(100).optional(), maxLength: z.number().int().positive().optional() })).optional(),
});

const playgroundLast = new Map<string, number>();

export function adminRoutes() {
  const app = new Hono<{ Variables: Vars }>();

  app.post("/login", async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as { email?: string; password?: string };
    const u = body.email ? await findUserByEmail(body.email) : undefined;
    const ip = clientIp(c);
    const email = (body.email ?? "").toLowerCase();
    if (loginBlocked(email, ip)) return c.json({ error: "Too many failed sign-ins. Try again in 15 minutes." }, 429);
    if (!u || !(await verifyPassword(body.password ?? "", u.password_hash))) {
      recordLoginFailure(email, ip);
      await auditSecurity({ tenantId: u?.tenant_id, userId: u?.id, event: "console_login_failed", decision: "deny", reason: "wrong password", detail: { ip } });
      return c.json({ error: "Wrong email or password." }, 401);
    }
    clearLoginFailures(email);
    setCookie(c, COOKIE, await sessionToken(u), {
      httpOnly: true,
      secure: config.publicUrl.startsWith("https"),
      sameSite: "Lax",
      path: "/api",
      maxAge: 8 * 3600,
    });
    return c.json({ ok: true });
  });
  app.post("/logout", (c) => {
    deleteCookie(c, COOKIE, { path: "/api" });
    return c.json({ ok: true });
  });
  app.get("/public", (c) =>
    c.json({
      demo: config.demo,
      mcpUrl: resourceUrl(),
      demoAccounts: config.demo
        ? [
            { email: "maya@acme.test", role: "Admin (eng, security, support)" },
            { email: "dana@acme.test", role: "Engineer (eng, security)" },
            { email: "sam@acme.test", role: "Support" },
          ]
        : [],
      demoPassword: config.demo ? "agentgate-demo" : undefined,
    }),
  );

  app.use("/*", requireUser);

  app.get("/me", async (c) => {
    const u = c.get("user");
    const full = await getUser(u.tenantId, u.id);
    const bundles = await userBundles(u.tenantId, full?.groups ?? []);
    return c.json({ ...u, groups: full?.groups ?? [], bundles: bundles.map((b) => b.id) });
  });

  app.get("/overview", async (c) => {
    const t = c.get("user").tenantId;
    const [totals, byTool, denials, timeline, agents] = await Promise.all([
      q<{ decision: string; n: string }>(
        "SELECT decision, count(*) AS n FROM audit_events WHERE tenant_id = $1 AND ts > now() - INTERVAL '7 days' GROUP BY decision",
        [t],
      ),
      q<{ tool: string; allowed: string; denied: string }>(
        `SELECT tool, count(*) FILTER (WHERE decision <> 'deny') AS allowed, count(*) FILTER (WHERE decision = 'deny') AS denied
         FROM audit_events WHERE tenant_id = $1 AND ts > now() - INTERVAL '7 days' GROUP BY tool ORDER BY count(*) DESC LIMIT 12`,
        [t],
      ),
      q(
        `SELECT seq, ts, tool, reason, agent_id, args_redacted FROM audit_events
         WHERE tenant_id = $1 AND decision = 'deny' ORDER BY seq DESC LIMIT 8`,
        [t],
      ),
      q<{ hour: string; allowed: string; denied: string }>(
        `SELECT date_trunc('hour', ts) AS hour, count(*) FILTER (WHERE decision <> 'deny') AS allowed, count(*) FILTER (WHERE decision = 'deny') AS denied
         FROM audit_events WHERE tenant_id = $1 AND ts > now() - INTERVAL '24 hours' GROUP BY 1 ORDER BY 1`,
        [t],
      ),
      q1<{ n: string }>("SELECT count(*) AS n FROM agents WHERE tenant_id = $1 AND NOT disabled AND name NOT LIKE 'eval-%' AND name NOT LIKE 'playground:%'", [t]),
    ]);
    return c.json({ totals, byTool, denials, timeline, agents: Number(agents?.n ?? 0), liveSessions: liveSessionCount(), connectors: connectors.map((x) => ({ id: x.id, name: x.name, tools: x.tools.length })) });
  });

  app.get("/audit", async (c) => {
    const t = c.get("user").tenantId;
    const { decision, tool, agent, session, before } = c.req.query();
    const limit = Math.min(Number(c.req.query("limit") ?? 50), 200);
    const where = ["tenant_id = $1"];
    const params: unknown[] = [t];
    const add = (sql: string, v: unknown) => {
      params.push(v);
      where.push(sql.replace("?", `$${params.length}`));
    };
    if (decision) add("decision = ?", decision);
    if (tool) add("tool = ?", tool);
    if (agent) add("agent_id = ?", agent);
    if (session) add("session_id = ?", session);
    if (before) add("seq < ?", Number(before));
    params.push(limit);
    const rows = await q(
      `SELECT seq, ts, user_id, agent_id, client_id, session_id, bundle_id, connector, tool, action, decision, reason, args_redacted,
              findings, flow, latency_ms, result_bytes, trace_id, prev_hash, hash
       FROM audit_events WHERE ${where.join(" AND ")} ORDER BY seq DESC LIMIT $${params.length}`,
      params,
    );
    return c.json(rows);
  });

  app.get("/audit/verify", async (c) => c.json(await verifyChain(c.get("user").tenantId)));

  app.get("/audit/export", async (c) => {
    const rows = await q("SELECT * FROM audit_events WHERE tenant_id = $1 ORDER BY seq", [c.get("user").tenantId]);
    c.header("content-type", "application/x-ndjson");
    c.header("content-disposition", 'attachment; filename="agentgate-audit.ndjson"');
    return c.body(rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
  });

  app.get("/bundles", async (c) => {
    const rows = await q("SELECT id, name, description, rules, updated_at FROM bundles WHERE tenant_id = $1 ORDER BY id", [c.get("user").tenantId]);
    const groups = await q<{ grp: string; bundle_id: string }>("SELECT grp, bundle_id FROM group_bundles WHERE tenant_id = $1", [c.get("user").tenantId]);
    return c.json({ bundles: rows, groups, tools: allTools().map((t) => ({ name: t.name, action: t.action, risk: t.risk, description: t.description })) });
  });

  app.put("/bundles/:id", requireAdmin, async (c) => {
    const body = z.object({ name: z.string().min(1).max(80), description: z.string().max(300), rules: z.array(ruleSchema).min(1).max(50) }).safeParse(await c.req.json());
    if (!body.success) return c.json({ error: body.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ") }, 400);
    const id = c.req.param("id") ?? "";
    if (!/^[a-z0-9-]{2,40}$/.test(id)) return c.json({ error: "bundle id must be lowercase letters, digits and dashes" }, 400);
    await auditSecurity({ tenantId: c.get("user").tenantId, userId: c.get("user").id, event: "bundle_changed", decision: "allow", reason: `bundle ${id} updated by ${c.get("user").email}`, detail: { rules: body.data.rules } });
    await q("UPSERT INTO bundles (tenant_id, id, name, description, rules, updated_at) VALUES ($1,$2,$3,$4,$5, now())", [
      c.get("user").tenantId,
      id,
      body.data.name,
      body.data.description,
      JSON.stringify(body.data.rules),
    ]);
    clearPolicyCaches();
    return c.json({ ok: true });
  });

  app.get("/agents", async (c) => {
    const rows = await q(
      `SELECT a.id, a.name, a.bundle_id, a.disabled, a.created_at, u.email AS owner,
              (SELECT count(*) FROM audit_events e WHERE e.tenant_id = a.tenant_id AND e.agent_id = a.id) AS calls
       FROM agents a JOIN users u ON u.tenant_id = a.tenant_id AND u.id = a.owner_user_id
       WHERE a.tenant_id = $1 AND ((a.name NOT LIKE 'eval-%' AND a.name NOT LIKE 'playground:%') OR $2) ORDER BY a.created_at DESC LIMIT 100`,
      [c.get("user").tenantId, c.req.query("all") === "1"],
    );
    return c.json(rows);
  });

  app.post("/agents", async (c) => {
    const u = c.get("user");
    const body = z.object({ name: z.string().min(2).max(60), bundle: z.string() }).safeParse(await c.req.json());
    if (!body.success) return c.json({ error: "name and bundle are required" }, 400);
    const full = await getUser(u.tenantId, u.id);
    const allowed = await userBundles(u.tenantId, full?.groups ?? []);
    if (!allowed.some((b) => b.id === body.data.bundle)) return c.json({ error: "you can only grant bundles your role allows" }, 403);
    const count = await q1<{ n: string }>("SELECT count(*) AS n FROM agents WHERE tenant_id = $1 AND owner_user_id = $2", [u.tenantId, u.id]);
    if (config.demo && Number(count?.n) > 50) return c.json({ error: "demo limit reached" }, 429);
    const a = await q1<{ id: string }>("INSERT INTO agents (tenant_id, name, owner_user_id, bundle_id) VALUES ($1,$2,$3,$4) RETURNING id", [
      u.tenantId,
      body.data.name,
      u.id,
      body.data.bundle,
    ]);
    const creds = await createAgentClient(u.tenantId, a!.id, body.data.name);
    await auditSecurity({ tenantId: u.tenantId, userId: u.id, agentId: a!.id, event: "agent_created", decision: "allow", reason: `bundle ${body.data.bundle}`, detail: { name: body.data.name } });
    return c.json({ id: a!.id, ...creds, tokenUrl: `${config.publicUrl}/oauth/token`, mcpUrl: resourceUrl(), note: "The client secret is shown once." });
  });

  app.post("/agents/:id/disable", async (c) => {
    const u = c.get("user");
    const a = await q1<{ owner_user_id: string }>("SELECT owner_user_id FROM agents WHERE tenant_id = $1 AND id = $2", [u.tenantId, c.req.param("id")]);
    if (!a) return c.json({ error: "not found" }, 404);
    if (a.owner_user_id !== u.id && !u.admin) return c.json({ error: "only the owner or an admin can disable an agent" }, 403);
    await q("UPDATE agents SET disabled = true WHERE tenant_id = $1 AND id = $2", [u.tenantId, c.req.param("id")]);
    await q("UPSERT INTO revoked_families (family_id) VALUES ($1)", [c.req.param("id")]); // kills live tokens
    await auditSecurity({ tenantId: u.tenantId, userId: u.id, agentId: c.req.param("id"), event: "agent_disabled", decision: "allow", reason: `disabled by ${u.email}` });
    return c.json({ ok: true });
  });

  app.get("/agents/:id/blast-radius", async (c) => {
    const r = await blastRadius(c.get("user").tenantId, c.req.param("id"));
    return r ? c.json(r) : c.json({ error: "not found" }, 404);
  });

  app.get("/sessions", async (c) => {
    const rows = await q(
      `SELECT s.id, s.client_id, s.bundle_id, s.agent_id, s.level, s.sources, s.untrusted, s.created_at, s.last_seen,
              (SELECT count(*) FROM audit_events e WHERE e.tenant_id = s.tenant_id AND e.session_id = s.id) AS calls,
              (SELECT count(*) FROM audit_events e WHERE e.tenant_id = s.tenant_id AND e.session_id = s.id AND e.decision = 'deny') AS denied
       FROM mcp_sessions s WHERE s.tenant_id = $1 ORDER BY s.last_seen DESC LIMIT 40`,
      [c.get("user").tenantId],
    );
    return c.json(rows);
  });

  app.get("/credentials", async (c) => {
    const rows = await q(
      `SELECT id, connector, user_id, kek_version, scopes, created_at, rotated_at FROM credentials WHERE tenant_id = $1 ORDER BY connector`,
      [c.get("user").tenantId],
    );
    return c.json({ activeKekVersion: getVault().activeVersion, credentials: rows });
  });

  app.post("/credentials/rewrap", requireAdmin, async (c) => {
    const t = c.get("user").tenantId;
    const vault = getVault();
    const rows = await q<{ id: string; user_id: string | null; connector: string; ciphertext: Buffer; wrapped_key: Buffer; kek_version: string }>(
      "SELECT id, user_id, connector, ciphertext, wrapped_key, kek_version FROM credentials WHERE tenant_id = $1",
      [t],
    );
    let rewrapped = 0;
    for (const r of rows) {
      const s = { ciphertext: r.ciphertext, wrappedKey: r.wrapped_key, kekVersion: Number(r.kek_version) };
      const n = vault.rewrap(s, credentialAad(t, r.user_id, r.connector));
      if (n.kekVersion !== s.kekVersion) {
        await q("UPDATE credentials SET wrapped_key = $3, kek_version = $4, rotated_at = now() WHERE tenant_id = $1 AND id = $2", [t, r.id, n.wrappedKey, n.kekVersion]);
        rewrapped++;
      }
    }
    return c.json({ rewrapped, activeKekVersion: vault.activeVersion });
  });

  app.post("/keys/rotate", requireAdmin, async (c) => {
    const r = await rotateSigningKey({ force: true });
    await auditSecurity({ tenantId: c.get("user").tenantId, userId: c.get("user").id, event: "signing_key_rotated", decision: "allow", reason: `new key ${r.kid}` });
    return c.json(r);
  });

  app.get("/traces", (c) => {
    const limit = Math.min(Number(c.req.query("limit") ?? 300), 2000);
    return c.json(spanStore.spans.slice(-limit));
  });

  app.get("/redteam", async (c) => {
    const rows = await q<{ agent: string; created_at: string; report: unknown }>(
      `SELECT agent, created_at, report FROM (
         SELECT agent, created_at, report, row_number() OVER (PARTITION BY split_part(agent, ':', 1) ORDER BY created_at DESC) AS rn
         FROM redteam_runs) WHERE rn = 1 ORDER BY agent`,
    );
    return c.json(rows);
  });

  app.get("/playground/scenarios", (c) =>
    c.json(SCENARIOS.map((s) => ({ id: s.id, title: s.title, kind: s.kind, bundle: s.bundle, owner: s.owner, task: s.task, steps: s.scripted }))),
  );

  app.post("/playground/run", async (c) => {
    const u = c.get("user");
    const body = z.object({ scenario: z.string(), mode: z.enum(["gateway", "direct"]) }).safeParse(await c.req.json());
    if (!body.success) return c.json({ error: "scenario and mode are required" }, 400);
    const s = SCENARIOS.find((x) => x.id === body.data.scenario);
    if (!s) return c.json({ error: "unknown scenario" }, 404);
    if (!config.demo) return c.json({ error: "the playground runs only in demo mode" }, 403);
    const last = playgroundLast.get(u.id) ?? 0;
    if (Date.now() - last < 2000) return c.json({ error: "one run every 2 seconds" }, 429);
    playgroundLast.set(u.id, Date.now());
    return c.json(await runScenario(s, body.data.mode, "scripted", { runLabel: "playground" }));
  });

  app.get("/sim/state", (c) =>
    c.json({
      writes: sim.writes,
      repos: sim.repos.map((r) => r.full_name),
      channels: sim.channels.map((ch) => ({ name: ch.name, messages: ch.messages.length })),
    }),
  );

  return app;
}
