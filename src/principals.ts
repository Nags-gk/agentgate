import { q, q1 } from "./db/index.js";
import { cache } from "./cache.js";
import type { Bundle, Rule } from "./policy.js";

export interface UserRow {
  tenant_id: string;
  id: string;
  email: string;
  display_name: string;
  password_hash: string;
  is_admin: boolean;
  groups: string[];
}

export const findUserByEmail = (email: string) =>
  q1<UserRow>("SELECT tenant_id, id, email, display_name, password_hash, is_admin, groups FROM users WHERE email = $1", [email.toLowerCase().trim()]);

export const getUser = (tenantId: string, id: string) =>
  q1<UserRow>("SELECT tenant_id, id, email, display_name, password_hash, is_admin, groups FROM users WHERE tenant_id = $1 AND id = $2", [tenantId, id]);

const toBundle = (r: { id: string; name: string; description: string; rules: Rule[] }): Bundle => ({
  id: r.id,
  name: r.name,
  description: r.description,
  rules: r.rules,
});

export async function getBundle(tenantId: string, id: string): Promise<Bundle | undefined> {
  const r = await q1<{ id: string; name: string; description: string; rules: Rule[] }>(
    "SELECT id, name, description, rules FROM bundles WHERE tenant_id = $1 AND id = $2",
    [tenantId, id],
  );
  return r && toBundle(r);
}

/** The bundles a user's groups may use: the user's ceiling, and the bundles they may grant. */
export async function userBundles(tenantId: string, groups: string[]): Promise<Bundle[]> {
  if (!groups.length) return [];
  const rows = await q<{ id: string; name: string; description: string; rules: Rule[] }>(
    `SELECT DISTINCT b.id, b.name, b.description, b.rules FROM bundles b
     JOIN group_bundles g ON g.tenant_id = b.tenant_id AND g.bundle_id = b.id
     WHERE b.tenant_id = $1 AND g.grp = ANY($2) ORDER BY b.id`,
    [tenantId, groups],
  );
  return rows.map(toBundle);
}

export interface TenantSettings {
  labels?: Record<string, string>;
  connectors?: Record<string, { baseUrl?: string }>;
}
const settingsCache = cache<TenantSettings>();
export const tenantSettings = (tenantId: string) =>
  settingsCache.get(tenantId, async () => (await q1<{ settings: TenantSettings }>("SELECT settings FROM tenants WHERE id = $1", [tenantId]))?.settings ?? {});

export async function tenantLabels(tenantId: string): Promise<Record<string, string>> {
  return (await tenantSettings(tenantId)).labels ?? {};
}

const userCache = cache<UserRow | undefined>();
const bundleCache = cache<Bundle | undefined>();
const ceilingCache = cache<Bundle[]>();
export const getUserCached = (tenantId: string, id: string) => userCache.get(`${tenantId}:${id}`, () => getUser(tenantId, id));
export const getBundleCached = (tenantId: string, id: string) => bundleCache.get(`${tenantId}:${id}`, () => getBundle(tenantId, id));
export const userBundlesCached = (tenantId: string, groups: string[]) =>
  ceilingCache.get(`${tenantId}:${[...groups].sort().join(",")}`, () => userBundles(tenantId, groups));
