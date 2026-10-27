import { createHash, randomBytes } from "node:crypto";
import type { ServerType } from "@hono/node-server";
import { serve } from "@hono/node-server";
import pg from "pg";

export const BASE = process.env.PUBLIC_URL!;
let server: ServerType | undefined;

/** Fresh database per test run, then the real app on a local port. */
export async function startApp() {
  const url = new URL(process.env.DATABASE_URL!);
  const dbName = url.pathname.slice(1);
  url.pathname = "/defaultdb";
  const admin = new pg.Client({ connectionString: url.toString() });
  await admin.connect();
  await admin.query(`DROP DATABASE IF EXISTS ${dbName} CASCADE`);
  await admin.query(`CREATE DATABASE ${dbName}`);
  await admin.end();

  const { migrate } = await import("../src/db/migrate.js");
  const { seedDemo } = await import("../src/seed.js");
  const { signingKey } = await import("../src/auth/crypto.js");
  const { startConnectors } = await import("../src/gateway/registry.js");
  const { buildApp } = await import("../src/app.js");
  await migrate(false);
  await signingKey();
  const seeded = await seedDemo();
  await startConnectors();
  server = serve({ fetch: buildApp().fetch, port: Number(process.env.PORT), hostname: "127.0.0.1" });
  await new Promise((r) => setTimeout(r, 100));
  return seeded;
}

export async function stopApp() {
  server?.close();
  const { stopConnectors } = await import("../src/gateway/registry.js");
  const { closeDb } = await import("../src/db/index.js");
  await stopConnectors();
  await closeDb();
}

export const pkce = () => {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
};

export async function register(redirect = "http://127.0.0.1:9999/callback") {
  const r = await fetch(`${BASE}/oauth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_name: "Test Client", redirect_uris: [redirect] }),
  });
  return { status: r.status, body: (await r.json()) as { client_id: string }, redirect };
}

const form = (o: Record<string, string>) => new URLSearchParams(o).toString();

/** Drive the browser part of the flow: sign in, pick a bundle, get the code from the redirect. */
export async function authorizeCode(opts: { clientId: string; redirect: string; challenge: string; email?: string; password?: string; bundle?: string; resource?: string }) {
  const params = {
    response_type: "code",
    client_id: opts.clientId,
    redirect_uri: opts.redirect,
    code_challenge: opts.challenge,
    code_challenge_method: "S256",
    state: "xyz",
    resource: opts.resource ?? `${BASE}/mcp`,
  };
  const step1 = await fetch(`${BASE}/oauth/authorize`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form({ ...params, email: opts.email ?? "dana@acme.test", password: opts.password ?? "agentgate-demo" }),
    redirect: "manual",
  });
  const html = await step1.text();
  const ticket = /name="ticket" value="([^"]+)"/.exec(html)?.[1];
  if (!ticket) return { status: step1.status, html };
  const step2 = await fetch(`${BASE}/oauth/authorize`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form({ ...params, ticket, bundle: opts.bundle ?? "issue-triage", decision: "allow" }),
    redirect: "manual",
  });
  const loc = step2.headers.get("location");
  return { status: step2.status, location: loc, code: loc ? new URL(loc).searchParams.get("code") : null, html: loc ? "" : await step2.text() };
}

export async function token(body: Record<string, string>, headers: Record<string, string> = {}) {
  const r = await fetch(`${BASE}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
    body: form(body),
  });
  return { status: r.status, body: (await r.json()) as Record<string, string> };
}

/** Full user flow -> access + refresh tokens for a bundle. */
export async function loginTokens(bundle = "issue-triage", email = "dana@acme.test") {
  const reg = await register();
  const p = pkce();
  const a = await authorizeCode({ clientId: reg.body.client_id, redirect: reg.redirect, challenge: p.challenge, bundle, email });
  const t = await token({ grant_type: "authorization_code", code: a.code!, redirect_uri: reg.redirect, client_id: reg.body.client_id, code_verifier: p.verifier });
  return { clientId: reg.body.client_id, ...t.body } as { clientId: string; access_token: string; refresh_token: string };
}
