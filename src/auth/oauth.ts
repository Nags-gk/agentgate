import { Hono, type Context } from "hono";
import { config, resourceUrl } from "../config.js";
import { q, q1 } from "../db/index.js";
import { findUserByEmail, getUser, userBundles } from "../principals.js";
import { SignJWT, jwtVerify, createLocalJWKSet } from "jose";
import { metrics } from "../telemetry.js";
import { hashPassword, jwks, randomToken, safeEqual, sha256, signingKey, verifyPassword, verifyPkce } from "./crypto.js";
import { OAuthError, issueAccessToken, issueTokens, revokeFamilyOf, rotateRefresh } from "./tokens.js";
import { consentPage, errorPage } from "./pages.js";
import { auditSecurity, clearLoginFailures, loginBlocked, recordLoginFailure } from "../security.js";
import { getConnInfo } from "@hono/node-server/conninfo";

/**
 * OAuth 2.1 authorization server for MCP clients, following the MCP authorization spec:
 *  - RFC 9728 protected-resource metadata and RFC 8414 server metadata for discovery
 *  - RFC 7591 dynamic client registration (Claude, Cursor and other clients self-register)
 *  - authorization code + PKCE (S256 only), exact redirect-URI match, single-use codes
 *  - RFC 8707 resource indicators: tokens are audience-bound to this gateway's /mcp
 *  - refresh-token rotation with reuse detection
 *  - client_credentials for service agents, capped by their own bundle
 */

const CODE_TTL_SEC = 60;
// A real scrypt hash of a random password, verified against when the email is unknown.
const DUMMY_HASH = "scrypt$32768$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

export function clientIp(c: Context): string {
  const xff = c.req.header("x-forwarded-for");
  if (xff) return xff.split(",")[0]!.trim(); // Cloud Run's front end sets this
  try {
    return getConnInfo(c).remote.address ?? "unknown";
  } catch {
    return "unknown";
  }
}
const TICKET_TTL_SEC = 300;

async function makeTicket(tenantId: string, userId: string, clientId: string): Promise<string> {
  const k = await signingKey();
  return new SignJWT({ tid: tenantId, cid: clientId })
    .setProtectedHeader({ alg: "ES256", kid: k.kid, typ: "login+jwt" })
    .setSubject(userId)
    .setAudience(`${config.publicUrl}/oauth/authorize`)
    .setIssuedAt()
    .setExpirationTime(`${TICKET_TTL_SEC}s`)
    .sign(k.privateKey);
}

async function readTicket(ticket: string, clientId: string) {
  try {
    await signingKey();
    const { payload } = await jwtVerify(ticket, createLocalJWKSet(jwks()), {
      audience: `${config.publicUrl}/oauth/authorize`,
      typ: "login+jwt",
      algorithms: ["ES256"],
    });
    if (payload.cid !== clientId || !payload.sub) return undefined;
    return getUser(String(payload.tid), payload.sub);
  } catch {
    return undefined;
  }
}

export const protectedResourceMetadata = () => ({
  resource: resourceUrl(),
  authorization_servers: [config.publicUrl],
  bearer_methods_supported: ["header"],
  resource_name: "AgentGate MCP gateway",
  resource_documentation: `${config.publicUrl}/docs`,
});

export const authServerMetadata = () => ({
  issuer: config.publicUrl,
  authorization_endpoint: `${config.publicUrl}/oauth/authorize`,
  token_endpoint: `${config.publicUrl}/oauth/token`,
  registration_endpoint: `${config.publicUrl}/oauth/register`,
  revocation_endpoint: `${config.publicUrl}/oauth/revoke`,
  jwks_uri: `${config.publicUrl}/oauth/jwks`,
  response_types_supported: ["code"],
  grant_types_supported: ["authorization_code", "refresh_token", "client_credentials"],
  code_challenge_methods_supported: ["S256"],
  token_endpoint_auth_methods_supported: ["none", "client_secret_basic", "client_secret_post"],
  scopes_supported: ["mcp"],
});

/** Redirect URIs must be HTTPS, or HTTP on loopback (native apps, RFC 8252), with no fragment. */
export function validRedirectUri(u: string): boolean {
  try {
    const url = new URL(u);
    if (url.hash) return false;
    if (url.protocol === "https:") return true;
    if (url.protocol === "http:") return ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    // Custom schemes for desktop apps (e.g. cursor://) are allowed when they are not web schemes.
    return /^[a-z][a-z0-9+.-]*:$/.test(url.protocol) && !["javascript:", "data:", "file:", "vbscript:"].includes(url.protocol);
  } catch {
    return false;
  }
}

interface ClientRow {
  client_id: string;
  tenant_id: string | null;
  name: string;
  redirect_uris: string[];
  secret_hash: string | null;
  agent_id: string | null;
  grant_types: string[];
}
const getClient = (id: string) =>
  q1<ClientRow>("SELECT client_id, tenant_id, name, redirect_uris, secret_hash, agent_id, grant_types FROM oauth_clients WHERE client_id = $1", [id]);

function oauthError(c: Context, e: OAuthError) {
  return c.json({ error: e.error, error_description: e.description }, e.status as 400 | 401);
}

/** Client authentication at the token endpoint: secret_basic, secret_post, or none (public PKCE clients). */
function clientCredentials(c: Context, form: Record<string, string>): { id?: string; secret?: string } {
  const h = c.req.header("authorization");
  if (h?.startsWith("Basic ")) {
    const [id, secret] = Buffer.from(h.slice(6), "base64").toString().split(":");
    return { id: decodeURIComponent(id ?? ""), secret: decodeURIComponent(secret ?? "") };
  }
  return { id: form.client_id, secret: form.client_secret };
}

export function oauthRoutes() {
  const app = new Hono();

  app.get("/.well-known/oauth-protected-resource", (c) => c.json(protectedResourceMetadata()));
  app.get("/.well-known/oauth-protected-resource/mcp", (c) => c.json(protectedResourceMetadata()));
  app.get("/.well-known/oauth-authorization-server", (c) => c.json(authServerMetadata()));
  app.get("/.well-known/openid-configuration", (c) => c.json(authServerMetadata()));
  app.get("/oauth/jwks", (c) => c.json(jwks()));

  // ---------------------------------------------------------------- dynamic registration
  app.post("/oauth/register", async (c) => {
    let body: Record<string, unknown>;
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "invalid_client_metadata", error_description: "body must be JSON" }, 400);
    }
    const uris = Array.isArray(body.redirect_uris) ? body.redirect_uris.filter((u): u is string => typeof u === "string") : [];
    if (!uris.length || uris.length > 10 || !uris.every(validRedirectUri))
      return c.json({ error: "invalid_redirect_uri", error_description: "redirect_uris must be https, loopback http, or an app scheme" }, 400);
    const name = typeof body.client_name === "string" ? body.client_name.slice(0, 100) : "MCP client";
    const clientId = `mcp_${randomToken(12)}`;
    await q("INSERT INTO oauth_clients (client_id, name, redirect_uris, grant_types) VALUES ($1,$2,$3,$4)", [
      clientId,
      name,
      uris,
      ["authorization_code", "refresh_token"],
    ]);
    metrics.authEvents.inc({ event: "client_registered" });
    return c.json(
      {
        client_id: clientId,
        client_name: name,
        redirect_uris: uris,
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
        client_id_issued_at: Math.floor(Date.now() / 1000),
      },
      201,
    );
  });

  // ---------------------------------------------------------------- authorize
  async function validateAuthorize(p: Record<string, string | undefined>) {
    if (p.response_type !== "code") throw new OAuthError("unsupported_response_type", "response_type must be code");
    const client = p.client_id ? await getClient(p.client_id) : undefined;
    if (!client) throw new OAuthError("invalid_client", "unknown client_id");
    if (!p.redirect_uri || !client.redirect_uris.includes(p.redirect_uri)) throw new OAuthError("invalid_request", "redirect_uri does not match a registered URI");
    if (!p.code_challenge || p.code_challenge_method !== "S256") throw new OAuthError("invalid_request", "PKCE with code_challenge_method=S256 is required");
    const resource = p.resource ?? resourceUrl();
    if (resource.replace(/\/$/, "") !== resourceUrl()) throw new OAuthError("invalid_target", `resource must be ${resourceUrl()}`);
    return { client, resource };
  }

  app.get("/oauth/authorize", async (c) => {
    const p = c.req.query();
    try {
      const { client } = await validateAuthorize(p);
      return c.html(consentPage({ clientName: client.name, params: p, demo: config.demo }));
    } catch (e) {
      // Never redirect to an unvalidated redirect_uri: show the error here instead.
      return c.html(errorPage((e as Error).message), 400);
    }
  });

  app.post("/oauth/authorize", async (c) => {
    const form = (await c.req.parseBody()) as Record<string, string>;
    let ctx: Awaited<ReturnType<typeof validateAuthorize>>;
    try {
      ctx = await validateAuthorize(form);
    } catch (e) {
      return c.html(errorPage((e as Error).message), 400);
    }
    const redirect = (params: Record<string, string>) => {
      const url = new URL(form.redirect_uri!);
      for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
      if (form.state) url.searchParams.set("state", form.state);
      url.searchParams.set("iss", config.publicUrl); // RFC 9207 mix-up protection
      return c.redirect(url.toString(), 302);
    };
    if (form.decision === "deny") return redirect({ error: "access_denied" });

    // Step 1: password -> short-lived signed login ticket (the password is never echoed back
    // into the page). Step 2: ticket + chosen bundle -> authorization code.
    let user: Awaited<ReturnType<typeof getUser>>;
    if (form.ticket) {
      user = await readTicket(form.ticket, ctx.client.client_id);
      if (!user) return c.html(errorPage("Your sign-in expired. Start again from the app."), 400);
    } else {
      const ip = clientIp(c);
      const email = (form.email ?? "").toLowerCase();
      if (loginBlocked(email, ip)) {
        metrics.authEvents.inc({ event: "login_throttled" });
        return c.html(consentPage({ clientName: ctx.client.name, params: form, demo: config.demo, error: "Too many failed sign-ins. Try again in 15 minutes." }), 429);
      }
      user = email ? await findUserByEmail(email) : undefined;
      // Hash even for unknown emails so response time does not reveal which accounts exist.
      const ok = await verifyPassword(form.password ?? "", user?.password_hash ?? DUMMY_HASH);
      if (!user || !ok) {
        recordLoginFailure(email, ip);
        metrics.authEvents.inc({ event: "login_failed" });
        await auditSecurity({ tenantId: user?.tenant_id, userId: user?.id, clientId: ctx.client.client_id, event: "login_failed", decision: "deny", reason: "wrong password", detail: { ip } });
        return c.html(consentPage({ clientName: ctx.client.name, params: form, demo: config.demo, error: "Wrong email or password." }), 401);
      }
      clearLoginFailures(email);
    }
    const bundles = await userBundles(user.tenant_id, user.groups);
    if (!form.ticket) {
      const ticket = await makeTicket(user.tenant_id, user.id, ctx.client.client_id);
      return c.html(consentPage({ clientName: ctx.client.name, params: form, demo: config.demo, user, bundles, ticket }));
    }
    const bundle = bundles.find((b) => b.id === form.bundle);
    if (!bundle) return c.html(errorPage("That access level is not available to your role."), 403);
    const code = randomToken();
    await q(
      `INSERT INTO auth_codes (code_hash, client_id, tenant_id, user_id, bundle_id, redirect_uri, code_challenge, resource, expires_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8, now() + $9::INT8 * INTERVAL '1 second')`,
      [sha256(code), ctx.client.client_id, user.tenant_id, user.id, bundle.id, form.redirect_uri, form.code_challenge, ctx.resource, CODE_TTL_SEC],
    );
    metrics.authEvents.inc({ event: "code_issued" });
    await auditSecurity({ tenantId: user.tenant_id, userId: user.id, clientId: ctx.client.client_id, event: "consent_granted", decision: "allow", reason: `granted bundle ${bundle.id} to ${ctx.client.name}`, detail: { bundle: bundle.id, client: ctx.client.name } });
    return redirect({ code });
  });

  // ---------------------------------------------------------------- token
  app.post("/oauth/token", async (c) => {
    const form = (await c.req.parseBody()) as Record<string, string>;
    c.header("Cache-Control", "no-store");
    try {
      const cred = clientCredentials(c, form);
      const client = cred.id ? await getClient(cred.id) : undefined;
      if (!client) throw new OAuthError("invalid_client", "unknown client", 401);
      if (client.secret_hash && !(cred.secret && safeEqual(sha256(cred.secret), client.secret_hash)))
        throw new OAuthError("invalid_client", "client authentication failed", 401);
      if (!client.grant_types.includes(form.grant_type ?? "")) throw new OAuthError("unauthorized_client", `grant_type ${form.grant_type} is not allowed for this client`);

      if (form.grant_type === "authorization_code") {
        const row = await q1<{
          client_id: string;
          tenant_id: string;
          user_id: string;
          bundle_id: string;
          redirect_uri: string;
          code_challenge: string;
          resource: string;
          expired: boolean;
        }>(
          // Claim the code in one statement (used = false -> true), so a code redeems at most once
          // even when two requests race.
          `UPDATE auth_codes SET used = true WHERE code_hash = $1 AND used = false
           RETURNING client_id, tenant_id, user_id, bundle_id, redirect_uri, code_challenge, resource, expires_at < now() AS expired`,
          [sha256(form.code ?? "")],
        );
        if (!row || row.expired) throw new OAuthError("invalid_grant", "authorization code is invalid or expired");
        if (row.client_id !== client.client_id) throw new OAuthError("invalid_grant", "code was issued to another client");
        if (row.redirect_uri !== form.redirect_uri) throw new OAuthError("invalid_grant", "redirect_uri mismatch");
        if (!verifyPkce(form.code_verifier ?? "", row.code_challenge)) throw new OAuthError("invalid_grant", "PKCE verification failed");
        if (form.resource && form.resource.replace(/\/$/, "") !== row.resource) throw new OAuthError("invalid_target", "resource mismatch");
        return c.json(await issueTokens({ tenantId: row.tenant_id, userId: row.user_id, clientId: client.client_id, bundleId: row.bundle_id, resource: row.resource }));
      }

      if (form.grant_type === "refresh_token") {
        return c.json(await rotateRefresh(form.refresh_token ?? "", client.client_id));
      }

      if (form.grant_type === "client_credentials") {
        if (!client.agent_id || !client.tenant_id) throw new OAuthError("unauthorized_client", "client is not a service agent");
        const agent = await q1<{ owner_user_id: string; bundle_id: string; disabled: boolean }>(
          "SELECT owner_user_id, bundle_id, disabled FROM agents WHERE tenant_id = $1 AND id = $2",
          [client.tenant_id, client.agent_id],
        );
        if (!agent || agent.disabled) throw new OAuthError("invalid_client", "agent is disabled", 401);
        const resource = (form.resource ?? resourceUrl()).replace(/\/$/, "");
        if (resource !== resourceUrl()) throw new OAuthError("invalid_target", `resource must be ${resourceUrl()}`);
        const token = await issueAccessToken({
          sub: agent.owner_user_id,
          aud: resource,
          tid: client.tenant_id,
          bid: agent.bundle_id,
          cid: client.client_id,
          fam: client.agent_id, // disabling the agent revokes every token it holds
          agt: client.agent_id,
        });
        metrics.authEvents.inc({ event: "agent_token_issued" });
        await auditSecurity({ tenantId: client.tenant_id, userId: agent.owner_user_id, agentId: client.agent_id, clientId: client.client_id, event: "agent_token_issued", decision: "allow", reason: `bundle ${agent.bundle_id}` });
        return c.json({ access_token: token, token_type: "Bearer", expires_in: config.accessTokenTtlSec, scope: `bundle:${agent.bundle_id}` });
      }
      throw new OAuthError("unsupported_grant_type", `grant_type ${form.grant_type} is not supported`);
    } catch (e) {
      if (e instanceof OAuthError) {
        metrics.authEvents.inc({ event: `token_error_${e.error}` });
        return oauthError(c, e);
      }
      throw e;
    }
  });

  app.post("/oauth/revoke", async (c) => {
    const form = (await c.req.parseBody()) as Record<string, string>;
    if (form.token) await revokeFamilyOf(form.token);
    return c.body(null, 200); // RFC 7009: always 200
  });

  return app;
}

/** Create a confidential client for a service agent; the secret is shown once. */
export async function createAgentClient(tenantId: string, agentId: string, name: string): Promise<{ clientId: string; clientSecret: string }> {
  const clientId = `agent_${randomToken(10)}`;
  const clientSecret = randomToken(32);
  await q("INSERT INTO oauth_clients (client_id, tenant_id, name, secret_hash, agent_id, grant_types) VALUES ($1,$2,$3,$4,$5,$6)", [
    clientId,
    tenantId,
    name,
    sha256(clientSecret),
    agentId,
    ["client_credentials"],
  ]);
  return { clientId, clientSecret };
}

export { hashPassword };
