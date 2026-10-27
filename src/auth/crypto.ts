import { createHash, randomBytes, scrypt as scryptCb, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { exportJWK, generateKeyPair, importJWK, type JWK, type CryptoKey } from "jose";
import { q } from "../db/index.js";
import { getVault } from "../vault.js";

const scrypt = promisify(scryptCb) as (pw: string, salt: Buffer, len: number, opts: object) => Promise<Buffer>;
const SCRYPT = { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

export async function hashPassword(pw: string): Promise<string> {
  const salt = randomBytes(16);
  const dk = await scrypt(pw, salt, 32, SCRYPT);
  return `scrypt$${SCRYPT.N}$${salt.toString("base64")}$${dk.toString("base64")}`;
}

export async function verifyPassword(pw: string, stored: string): Promise<boolean> {
  const [alg, n, salt, hash] = stored.split("$");
  if (alg !== "scrypt" || !salt || !hash) return false;
  const dk = await scrypt(pw, Buffer.from(salt, "base64"), 32, { ...SCRYPT, N: Number(n) });
  const want = Buffer.from(hash, "base64");
  return want.length === dk.length && timingSafeEqual(want, dk);
}

/** Opaque tokens (codes, refresh tokens, client secrets) are stored only as SHA-256 hashes. */
export const sha256 = (s: string) => createHash("sha256").update(s).digest("base64url");
export const randomToken = (bytes = 32) => randomBytes(bytes).toString("base64url");

export function verifyPkce(verifier: string, challenge: string): boolean {
  if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) return false;
  const a = Buffer.from(sha256(verifier));
  const b = Buffer.from(challenge);
  return a.length === b.length && timingSafeEqual(a, b);
}

export function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

// ------------------------------------------------------------ signing keys (ES256)

export interface SigningKey {
  kid: string;
  privateKey: CryptoKey;
  publicJwk: JWK;
}

let active: SigningKey | undefined;
let publicKeys: JWK[] = [];

/** Load the active signing key, creating one on first boot. The private half is vault-encrypted. */
export async function loadSigningKeys(): Promise<SigningKey> {
  const vault = getVault();
  const rows = await q<{ kid: string; private_enc: Buffer; wrapped_key: Buffer; kek_version: string; public_jwk: JWK; active: boolean }>(
    "SELECT kid, private_enc, wrapped_key, kek_version, public_jwk, active FROM signing_keys ORDER BY created_at DESC",
  );
  publicKeys = rows.map((r) => r.public_jwk);
  const cur = rows.find((r) => r.active);
  if (cur) {
    const jwk = JSON.parse(vault.decrypt({ ciphertext: cur.private_enc, wrappedKey: cur.wrapped_key, kekVersion: Number(cur.kek_version) }, `signing:${cur.kid}`));
    active = { kid: cur.kid, privateKey: (await importJWK(jwk, "ES256")) as CryptoKey, publicJwk: cur.public_jwk };
    return active;
  }
  const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
  const kid = randomToken(8);
  const pub = { ...(await exportJWK(publicKey)), kid, alg: "ES256", use: "sig" };
  const sealed = vault.encrypt(JSON.stringify(await exportJWK(privateKey)), `signing:${kid}`);
  await q(
    "INSERT INTO signing_keys (kid, private_enc, wrapped_key, kek_version, public_jwk) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (kid) DO NOTHING",
    [kid, sealed.ciphertext, sealed.wrappedKey, sealed.kekVersion, JSON.stringify(pub)],
  );
  // Another instance may have raced us; reload so every instance signs with the same key.
  return loadSigningKeysOnce();
}

let loading: Promise<SigningKey> | undefined;
async function loadSigningKeysOnce(): Promise<SigningKey> {
  const rows = await q<{ kid: string }>("SELECT kid FROM signing_keys WHERE active ORDER BY created_at LIMIT 1");
  if (rows.length) {
    await q("UPDATE signing_keys SET active = false WHERE active AND kid <> $1", [rows[0]!.kid]);
  }
  active = undefined;
  loading = undefined;
  return loadSigningKeys();
}

export async function signingKey(): Promise<SigningKey> {
  if (active) return active;
  loading ??= loadSigningKeys();
  return loading;
}

export const jwks = () => ({ keys: publicKeys.length ? publicKeys : active ? [active.publicJwk] : [] });

/**
 * Rotate the token-signing key when it is older than `maxAgeDays` (or when forced). The old
 * public key stays in the JWKS so tokens it signed keep verifying until they expire.
 */
export async function rotateSigningKey(opts: { maxAgeDays?: number; force?: boolean } = {}): Promise<{ rotated: boolean; kid: string }> {
  const cur = await q<{ kid: string; old: boolean }>(
    "SELECT kid, created_at < now() - $1::INT8 * INTERVAL '1 day' AS old FROM signing_keys WHERE active ORDER BY created_at DESC LIMIT 1",
    [opts.maxAgeDays ?? 30],
  );
  if (cur.length && !cur[0]!.old && !opts.force) return { rotated: false, kid: cur[0]!.kid };
  const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
  const kid = randomToken(8);
  const pub = { ...(await exportJWK(publicKey)), kid, alg: "ES256", use: "sig" };
  const sealed = getVault().encrypt(JSON.stringify(await exportJWK(privateKey)), `signing:${kid}`);
  await q("UPDATE signing_keys SET active = false WHERE active");
  await q("INSERT INTO signing_keys (kid, private_enc, wrapped_key, kek_version, public_jwk) VALUES ($1,$2,$3,$4,$5)", [
    kid,
    sealed.ciphertext,
    sealed.wrappedKey,
    sealed.kekVersion,
    JSON.stringify(pub),
  ]);
  // Retired keys older than 90 days leave the JWKS entirely.
  await q("DELETE FROM signing_keys WHERE NOT active AND created_at < now() - INTERVAL '90 days'");
  active = undefined;
  loading = undefined;
  await signingKey();
  return { rotated: true, kid };
}

/** Other instances pick up a rotation by reloading keys periodically. */
export async function reloadSigningKeys(): Promise<void> {
  active = undefined;
  loading = undefined;
  await signingKey();
}
