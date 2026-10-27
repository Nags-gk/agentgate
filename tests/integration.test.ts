import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { BASE, authorizeCode, loginTokens, pkce, register, startApp, stopApp, token } from "./helpers.js";

let tenantId: string;

beforeAll(async () => {
  ({ tenantId } = await startApp());
});
afterAll(stopApp);

async function mcp(accessToken: string) {
  const client = new Client({ name: "test", version: "1" });
  const transport = new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`), { requestInit: { headers: { authorization: `Bearer ${accessToken}` } } });
  await client.connect(transport);
  return { client, transport };
}
const text = (r: unknown) => ((r as { content: Array<{ text: string }> }).content ?? []).map((c) => c.text).join("\n");

describe("discovery", () => {
  it("advertises protected-resource and authorization-server metadata", async () => {
    const pr = await (await fetch(`${BASE}/.well-known/oauth-protected-resource/mcp`)).json();
    expect(pr.resource).toBe(`${BASE}/mcp`);
    const as = await (await fetch(`${BASE}/.well-known/oauth-authorization-server`)).json();
    expect(as.code_challenge_methods_supported).toEqual(["S256"]);
    expect(as.registration_endpoint).toBe(`${BASE}/oauth/register`);
  });
  it("answers an unauthenticated MCP call with 401 and a resource_metadata pointer", async () => {
    const r = await fetch(`${BASE}/mcp`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    expect(r.status).toBe(401);
    expect(r.headers.get("www-authenticate")).toContain("resource_metadata=");
  });
});

describe("OAuth 2.1 flow", () => {
  it("rejects unsafe redirect URIs at registration", async () => {
    const r = await register("http://evil.example/cb");
    expect(r.status).toBe(400);
  });

  it("issues tokens for code + PKCE and rejects replays, wrong verifiers and other resources", async () => {
    const reg = await register();
    const p = pkce();
    const a = await authorizeCode({ clientId: reg.body.client_id, redirect: reg.redirect, challenge: p.challenge });
    expect(a.status).toBe(302);
    expect(new URL(a.location!).searchParams.get("state")).toBe("xyz");
    expect(new URL(a.location!).searchParams.get("iss")).toBe(BASE);

    const bad = await token({ grant_type: "authorization_code", code: a.code!, redirect_uri: reg.redirect, client_id: reg.body.client_id, code_verifier: "x".repeat(43) });
    expect(bad.status).toBe(400);
    // The failed attempt consumed the code: single use, even when the first redemption fails.
    const replay = await token({ grant_type: "authorization_code", code: a.code!, redirect_uri: reg.redirect, client_id: reg.body.client_id, code_verifier: p.verifier });
    expect(replay.body.error).toBe("invalid_grant");

    const p2 = pkce();
    const a2 = await authorizeCode({ clientId: reg.body.client_id, redirect: reg.redirect, challenge: p2.challenge });
    const ok = await token({ grant_type: "authorization_code", code: a2.code!, redirect_uri: reg.redirect, client_id: reg.body.client_id, code_verifier: p2.verifier });
    expect(ok.status).toBe(200);
    expect(ok.body.token_type).toBe("Bearer");
    expect(ok.body.scope).toBe("bundle:issue-triage");
  });

  it("refuses a resource indicator for another server", async () => {
    const reg = await register();
    const p = pkce();
    const r = await authorizeCode({ clientId: reg.body.client_id, redirect: reg.redirect, challenge: p.challenge, resource: "https://other.example/mcp" });
    expect(r.status).toBe(400);
  });

  it("will not grant a bundle outside the user's role", async () => {
    const reg = await register();
    const p = pkce();
    const r = await authorizeCode({ clientId: reg.body.client_id, redirect: reg.redirect, challenge: p.challenge, email: "sam@acme.test", bundle: "engineering" });
    expect(r.status).toBe(403);
  });

  it("rejects a wrong password", async () => {
    const reg = await register();
    const r = await authorizeCode({ clientId: reg.body.client_id, redirect: reg.redirect, challenge: pkce().challenge, password: "nope" });
    expect(r.status).toBe(401);
  });

  it("rotates refresh tokens and revokes the family when an old one is replayed", async () => {
    const t = await loginTokens();
    const r1 = await token({ grant_type: "refresh_token", refresh_token: t.refresh_token, client_id: t.clientId });
    expect(r1.status).toBe(200);
    const replay = await token({ grant_type: "refresh_token", refresh_token: t.refresh_token, client_id: t.clientId });
    expect(replay.body.error).toBe("invalid_grant");
    // The newest token in the family is dead too, and so are access tokens minted from it.
    const r2 = await token({ grant_type: "refresh_token", refresh_token: r1.body.refresh_token!, client_id: t.clientId });
    expect(r2.body.error).toBe("invalid_grant");
    await new Promise((r) => setTimeout(r, 5200)); // revocation cache TTL
    const res = await fetch(`${BASE}/mcp`, { method: "POST", headers: { authorization: `Bearer ${r1.body.access_token}`, "content-type": "application/json" }, body: "{}" });
    expect(res.status).toBe(401);
  });
});

describe("MCP through the gateway", () => {
  it("lists only the tools in the granted bundle and annotates them", async () => {
    const t = await loginTokens("issue-triage");
    const { client } = await mcp(t.access_token);
    const tools = (await client.listTools()).tools;
    const names = tools.map((x) => x.name);
    expect(names).toContain("github_get_issue");
    expect(names).toContain("runbooks_search");
    expect(names).not.toContain("github_delete_repo");
    expect(names).not.toContain("github_get_file");
    expect(tools.find((x) => x.name === "github_get_issue")?.annotations?.readOnlyHint).toBe(true);
    await client.close();
  });

  it("calls upstream with a credential the agent never sees, and flags the planted injection", async () => {
    const t = await loginTokens("issue-triage");
    const { client } = await mcp(t.access_token);
    const r = await client.callTool({ name: "github_get_issue", arguments: { repo: "acme/website", number: 7 } });
    expect(r.isError).toBeFalsy();
    expect(text(r)).toContain("AgentGate notice");
    expect(text(r)).not.toContain("ghp_");
    await client.close();
  });

  it("blocks out-of-scope calls with an explanation", async () => {
    const t = await loginTokens("issue-triage");
    const { client } = await mcp(t.access_token);
    const r = await client.callTool({ name: "github_get_file", arguments: { repo: "acme/payments", path: "config/prod.env" } });
    expect(r.isError).toBe(true);
    expect(text(r)).toMatch(/Blocked by AgentGate \(policy\)/);
    await client.close();
  });

  it("redacts secrets in results and blocks confidential data from reaching a public channel", async () => {
    const t = await loginTokens("engineering");
    const { client } = await mcp(t.access_token);
    const f = await client.callTool({ name: "github_get_file", arguments: { repo: "acme/payments", path: "config/prod.env" } });
    expect(text(f)).toContain("[REDACTED:stripe_key]");
    expect(text(f)).not.toContain("sk_live_");
    const post = await client.callTool({ name: "slack_post_message", arguments: { channel: "#ext-partners", text: "summary" } });
    expect(post.isError).toBe(true);
    expect(text(post)).toMatch(/\(flow\).*confidential/);
    await client.close();
  });

  it("refuses to use a session created by another principal", async () => {
    const a = await loginTokens("issue-triage");
    const b = await loginTokens("read-only");
    const { client, transport } = await mcp(a.access_token);
    await client.listTools();
    const r = await fetch(`${BASE}/mcp`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${b.access_token}`,
        "mcp-session-id": transport.sessionId!,
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        "mcp-protocol-version": "2025-06-18",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 9, method: "tools/list" }),
    });
    expect(r.status).toBe(403);
    await client.close();
  });
});

describe("service agents (client_credentials)", () => {
  it("issues agent tokens, and disabling the agent revokes them", async () => {
    const login = await fetch(`${BASE}/api/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "dana@acme.test", password: "agentgate-demo" }),
    });
    const cookie = login.headers.get("set-cookie")!.split(";")[0]!;
    const h = { cookie, "content-type": "application/json", "x-agentgate": "1" };
    const created = await (await fetch(`${BASE}/api/agents`, { method: "POST", headers: h, body: JSON.stringify({ name: "ci-bot", bundle: "read-only" }) })).json();
    expect(created.clientSecret).toBeTruthy();

    const basic = "Basic " + Buffer.from(`${created.clientId}:${created.clientSecret}`).toString("base64");
    const t = await token({ grant_type: "client_credentials", resource: `${BASE}/mcp` }, { authorization: basic });
    expect(t.status).toBe(200);
    const wrong = await token({ grant_type: "client_credentials" }, { authorization: "Basic " + Buffer.from(`${created.clientId}:nope`).toString("base64") });
    expect(wrong.status).toBe(401);

    const { client } = await mcp(t.body.access_token!);
    expect((await client.listTools()).tools.every((x) => x.annotations?.readOnlyHint)).toBe(true);
    await client.close();

    const csrf = await fetch(`${BASE}/api/agents/${created.id}/disable`, { method: "POST", headers: { cookie } });
    expect(csrf.status).toBe(403); // missing anti-CSRF header
    await fetch(`${BASE}/api/agents/${created.id}/disable`, { method: "POST", headers: h });
    const after = await token({ grant_type: "client_credentials" }, { authorization: basic });
    expect(after.status).toBe(401);
    await new Promise((r) => setTimeout(r, 5200));
    const res = await fetch(`${BASE}/mcp`, { method: "POST", headers: { authorization: `Bearer ${t.body.access_token}`, "content-type": "application/json" }, body: "{}" });
    expect(res.status).toBe(401);

    const br = await (await fetch(`${BASE}/api/agents/${created.id}/blast-radius`, { headers: h })).json();
    expect(br.direct.tools).toBeGreaterThan(br.gateway.tools);
    expect(br.gateway.writeTools).toBe(0);
  });
});

describe("audit log", () => {
  it("is a verifiable hash chain that detects edits", async () => {
    const { verifyChain, appendAudit } = await import("../src/audit.js");
    const { q } = await import("../src/db/index.js");
    // Concurrent appends: CockroachDB serializes them on the chain head and the client retries.
    await Promise.all(
      Array.from({ length: 25 }, (_, i) => appendAudit({ tenantId, connector: "test", tool: `t${i}`, action: "read", decision: "allow", reason: "test" })),
    );
    const ok = await verifyChain(tenantId);
    expect(ok.ok).toBe(true);
    expect(ok.checked).toBeGreaterThan(25);
    const seqs = (await q<{ seq: string }>("SELECT seq FROM audit_events WHERE tenant_id = $1 ORDER BY seq", [tenantId])).map((r) => Number(r.seq));
    expect(seqs).toEqual(seqs.map((_, i) => seqs[0]! + i)); // no gaps, no duplicates

    await q("UPDATE audit_events SET reason = 'edited' WHERE tenant_id = $1 AND seq = $2", [tenantId, seqs[3]]);
    const bad = await verifyChain(tenantId);
    expect(bad.ok).toBe(false);
    expect(bad.brokenAt).toBe(seqs[3]);
  });
});

describe("sandbox", () => {
  it("contains a hostile stdio MCP server", async () => {
    const { SandboxedConnector } = await import("../src/connectors/sandbox.js");
    process.env.GEMINI_API_KEY ??= "must-not-leak";
    const evil = new SandboxedConnector({ id: "escape-test", name: "x", description: "", entry: "server.mjs", egress: [] });
    const r = await evil.call("escape-test_probe", {}, { signal: AbortSignal.timeout(20_000) });
    await evil.stop();
    const results = r.data as Record<string, { escaped: boolean; detail: string }>;
    expect(Object.keys(results).length).toBe(10);
    for (const [k, v] of Object.entries(results)) expect(v.escaped, `${k}: ${v.detail}`).toBe(false);
  });
});

describe("red-team suite (worst-case scripted agent)", () => {
  it("holds every attack through the gateway and keeps benign tasks working", async () => {
    const { runSuite } = await import("../src/agents/runner.js");
    const report = await runSuite("scripted");
    expect(report.summary.direct.attacksSucceeded).toBe(report.summary.direct.attacks);
    expect(report.summary.gateway.attacksSucceeded).toBe(0);
    expect(report.summary.gateway.benignDone).toBe(report.summary.gateway.benign);
  });
});

describe("fixes from the ThreatLens review", () => {
  it("throttles repeated failed sign-ins for an account", async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 6; i++) {
      const r = await fetch(`${BASE}/api/login`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-forwarded-for": "203.0.113.9" },
        body: JSON.stringify({ email: "sam@acme.test", password: `wrong-${i}` }),
      });
      statuses.push(r.status);
    }
    expect(statuses.slice(0, 5)).toEqual([401, 401, 401, 401, 401]);
    expect(statuses[5]).toBe(429);
    const { q } = await import("../src/db/index.js");
    const ev = await q("SELECT count(*) AS n FROM audit_events WHERE tenant_id = $1 AND tool = 'console_login_failed'", [tenantId]);
    expect(Number(ev[0]!.n)).toBeGreaterThanOrEqual(5);
  });

  it("rotates the signing key without breaking tokens signed by the old one", async () => {
    const before = await loginTokens("read-only");
    const { rotateSigningKey } = await import("../src/auth/crypto.js");
    const r = await rotateSigningKey({ force: true });
    expect(r.rotated).toBe(true);
    const jwks = await (await fetch(`${BASE}/oauth/jwks`)).json();
    expect(jwks.keys.length).toBeGreaterThanOrEqual(2);
    const { client } = await mcp(before.access_token);
    expect((await client.listTools()).tools.length).toBeGreaterThan(0);
    await client.close();
    const after = await loginTokens("read-only");
    const header = JSON.parse(Buffer.from(after.access_token.split(".")[0]!, "base64url").toString());
    expect(header.kid).toBe(r.kid);
  });

  it("quarantines an agent that keeps hitting blocked calls", async () => {
    const { q1 } = await import("../src/db/index.js");
    const { issueAccessToken } = await import("../src/auth/tokens.js");
    const owner = (await q1<{ id: string }>("SELECT id FROM users WHERE email = 'dana@acme.test'"))!;
    const agent = (await q1<{ id: string }>("INSERT INTO agents (tenant_id, name, owner_user_id, bundle_id) VALUES ($1, 'noisy-bot', $2, 'issue-triage') RETURNING id", [tenantId, owner.id]))!;
    const tok = await issueAccessToken({ sub: owner.id, aud: `${BASE}/mcp`, tid: tenantId, bid: "issue-triage", cid: "test", fam: agent.id, agt: agent.id });
    const { client } = await mcp(tok);
    let last = "";
    for (let i = 0; i < 8; i++) last = text(await client.callTool({ name: "github_delete_repo", arguments: { repo: "acme/infra" } }));
    expect(last).toContain("quarantined");
    await client.close();
    const row = await q1<{ disabled: boolean }>("SELECT disabled FROM agents WHERE id = $1", [agent.id]);
    expect(row!.disabled).toBe(true);
  });
});
