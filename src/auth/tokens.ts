import { randomUUID } from "node:crypto";
import { SignJWT, jwtVerify, createLocalJWKSet, decodeProtectedHeader, type JWTPayload } from "jose";
import { config, resourceUrl } from "../config.js";
import { q, q1, withTx } from "../db/index.js";
import { metrics } from "../telemetry.js";
import { jwks, randomToken, sha256, signingKey } from "./crypto.js";
import { auditSecurity } from "../security.js";

export interface GatewayClaims {
  tid: string; // tenant
  bid: string; // bundle the token was granted for
  cid: string; // OAuth client
  fam: string; // refresh-token family, or agent id (revocation)
  agt?: string; // service agent id, for machine tokens
}
export type AccessClaims = JWTPayload & GatewayClaims;

export interface TokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token?: string;
  scope: string;
}

export async function issueAccessToken(c: GatewayClaims & { sub: string; aud: string }): Promise<string> {
  const k = await signingKey();
  return new SignJWT({ tid: c.tid, bid: c.bid, cid: c.cid, fam: c.fam, ...(c.agt ? { agt: c.agt } : {}) })
    .setProtectedHeader({ alg: "ES256", kid: k.kid, typ: "at+jwt" })
    .setIssuer(config.publicUrl)
    .setSubject(c.sub)
    .setAudience(c.aud)
    .setIssuedAt()
    .setJti(randomUUID())
    .setExpirationTime(`${config.accessTokenTtlSec}s`)
    .sign(k.privateKey);
}

/** Issue an access token plus a new refresh token in `family` (a new family for a fresh login). */
export async function issueTokens(p: { tenantId: string; userId: string; clientId: string; bundleId: string; resource: string; family?: string }): Promise<TokenResponse> {
  const family = p.family ?? randomUUID();
  const refresh = randomToken();
  await q(
    `INSERT INTO refresh_tokens (token_hash, family_id, client_id, tenant_id, user_id, bundle_id, resource, expires_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7, now() + $8::INT8 * INTERVAL '1 second')`,
    [sha256(refresh), family, p.clientId, p.tenantId, p.userId, p.bundleId, p.resource, config.refreshTokenTtlSec],
  );
  const access = await issueAccessToken({ sub: p.userId, aud: p.resource, tid: p.tenantId, bid: p.bundleId, cid: p.clientId, fam: family });
  metrics.authEvents.inc({ event: "tokens_issued" });
  return { access_token: access, token_type: "Bearer", expires_in: config.accessTokenTtlSec, refresh_token: refresh, scope: `bundle:${p.bundleId}` };
}

export class OAuthError extends Error {
  constructor(
    readonly error: string,
    readonly description: string,
    readonly status = 400,
  ) {
    super(description);
  }
}

/**
 * Rotate a refresh token. Presenting a token that was already rotated means it was copied:
 * the whole family is revoked, which also invalidates access tokens minted from it.
 */
export async function rotateRefresh(token: string, clientId: string): Promise<TokenResponse> {
  const hash = sha256(token);
  const outcome = await withTx(async (tx) => {
    const row = await q1<{
      family_id: string;
      client_id: string;
      tenant_id: string;
      user_id: string;
      bundle_id: string;
      resource: string;
      rotated: boolean;
      revoked: boolean;
      expired: boolean;
    }>(
      `SELECT family_id, client_id, tenant_id, user_id, bundle_id, resource, rotated, revoked, expires_at < now() AS expired
       FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE`,
      [hash],
      tx,
    );
    if (!row || row.client_id !== clientId) return { kind: "invalid" as const };
    if (row.revoked || row.expired) return { kind: "invalid" as const };
    if (row.rotated) {
      await q("UPDATE refresh_tokens SET revoked = true WHERE family_id = $1", [row.family_id], tx);
      await q("UPSERT INTO revoked_families (family_id) VALUES ($1)", [row.family_id], tx);
      return { kind: "reuse" as const, row };
    }
    await q("UPDATE refresh_tokens SET rotated = true WHERE token_hash = $1", [hash], tx);
    return { kind: "ok" as const, row };
  });
  if (outcome.kind === "reuse") {
    metrics.authEvents.inc({ event: "refresh_reuse_detected" });
    await auditSecurity({
      tenantId: outcome.row.tenant_id,
      userId: outcome.row.user_id,
      clientId,
      event: "refresh_token_reuse",
      decision: "deny",
      reason: "an already-rotated refresh token was presented; the whole token family was revoked",
    });
    throw new OAuthError("invalid_grant", "refresh token was already used; the token family has been revoked");
  }
  if (outcome.kind === "invalid") throw new OAuthError("invalid_grant", "refresh token is invalid or expired");
  const r = outcome.row;
  metrics.authEvents.inc({ event: "refresh_rotated" });
  return issueTokens({ tenantId: r.tenant_id, userId: r.user_id, clientId, bundleId: r.bundle_id, resource: r.resource, family: r.family_id });
}

export async function revokeFamilyOf(token: string): Promise<void> {
  const row = await q1<{ family_id: string }>("SELECT family_id FROM refresh_tokens WHERE token_hash = $1", [sha256(token)]);
  if (!row) return;
  await q("UPDATE refresh_tokens SET revoked = true WHERE family_id = $1", [row.family_id]);
  await q("UPSERT INTO revoked_families (family_id) VALUES ($1)", [row.family_id]);
  revokedCache.delete(row.family_id);
}

// Revocation lookups are cached briefly; a revoked family stops working within REVOKE_TTL.
const REVOKE_TTL = 5_000;
const revokedCache = new Map<string, { revoked: boolean; at: number }>();
async function familyRevoked(fam: string): Promise<boolean> {
  const hit = revokedCache.get(fam);
  if (hit && Date.now() - hit.at < REVOKE_TTL) return hit.revoked;
  const revoked = !!(await q1("SELECT 1 FROM revoked_families WHERE family_id = $1", [fam]));
  revokedCache.set(fam, { revoked, at: Date.now() });
  if (revokedCache.size > 10_000) revokedCache.clear();
  return revoked;
}

export async function verifyAccessToken(token: string): Promise<AccessClaims> {
  await signingKey();
  const header = decodeProtectedHeader(token);
  if (header.alg !== "ES256") throw new OAuthError("invalid_token", "unsupported token algorithm", 401);
  const { payload } = await jwtVerify(token, createLocalJWKSet(jwks()), {
    issuer: config.publicUrl,
    audience: resourceUrl(), // RFC 8707: a token minted for another resource is rejected here
    algorithms: ["ES256"],
    typ: "at+jwt",
  });
  const c = payload as AccessClaims;
  if (!c.tid || !c.bid || !c.cid || !c.sub || !c.fam) throw new OAuthError("invalid_token", "token is missing required claims", 401);
  if (await familyRevoked(c.fam)) throw new OAuthError("invalid_token", "token has been revoked", 401);
  return c;
}
