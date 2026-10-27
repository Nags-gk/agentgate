import { closeDb, q, q1 } from "./db/index.js";
import { migrate } from "./db/migrate.js";
import { hashPassword } from "./auth/crypto.js";
import { credentialAad } from "./gateway/registry.js";
import type { Bundle } from "./policy.js";
import { SIM_TOKENS } from "./sim/index.js";
import { getVault } from "./vault.js";
import { clearPolicyCaches } from "./cache.js";

export const DEMO_PASSWORD = "agentgate-demo";
export const DEMO_TENANT = "acme";

export const DEMO_LABELS: Record<string, string> = {
  "github:acme/*": "internal",
  "github:acme/website": "public",
  "github:acme/payments": "confidential",
  "slack:#*": "internal",
  "slack:#ext-*": "public",
  "slack:#security-*": "confidential",
  "jira:*": "internal",
  "jira:SEC": "confidential",
  "runbooks:*": "internal",
};

export const DEMO_BUNDLES: Bundle[] = [
  {
    id: "engineering",
    name: "Engineering (full role)",
    description: "Everything an engineer may do by hand. A ceiling, rarely the right grant for an agent.",
    rules: [
      { tools: ["github_*"], resources: ["github:acme/*"] },
      { tools: ["github_list_repos"] },
      { tools: ["slack_list_channels"] },
      { tools: ["slack_*"], resources: ["slack:#general", "slack:#eng", "slack:#ext-partners"] },
      { tools: ["jira_*"], resources: ["jira:WEB"] },
      { tools: ["runbooks_*"] },
    ],
  },
  {
    id: "issue-triage",
    name: "Issue triage",
    description: "Read website issues, file Jira tickets in WEB, post updates to #eng.",
    rules: [
      { tools: ["github_list_issues", "github_get_issue", "github_comment_issue"], resources: ["github:acme/website"] },
      { tools: ["jira_search", "jira_get_issue", "jira_create_issue"], resources: ["jira:WEB"] },
      { tools: ["slack_post_message"], resources: ["slack:#eng"], args: { text: { maxLength: 1500 } } },
      { tools: ["runbooks_*"] },
    ],
  },
  {
    id: "read-only",
    name: "Read-only research",
    description: "Read anything the role can read. No writes.",
    rules: [
      { tools: ["github_list_repos", "github_list_issues", "github_get_issue", "github_get_file"] },
      { tools: ["slack_list_channels", "slack_read_channel"] },
      { tools: ["jira_search", "jira_get_issue"] },
      { tools: ["runbooks_*"] },
    ],
  },
  {
    id: "security",
    name: "Security response",
    description: "Security incidents in Jira SEC and #security-incidents.",
    rules: [
      { tools: ["jira_*"], resources: ["jira:SEC"] },
      { tools: ["slack_read_channel", "slack_post_message"], resources: ["slack:#security-incidents"] },
      { tools: ["github_get_file", "github_list_issues", "github_get_issue"], resources: ["github:acme/*"] },
      { tools: ["runbooks_*"] },
    ],
  },
  {
    id: "support-desk",
    name: "Support desk",
    description: "Answer partners in #ext-partners using public website issues and runbooks.",
    rules: [
      { tools: ["github_list_issues", "github_get_issue"], resources: ["github:acme/website"] },
      { tools: ["slack_read_channel", "slack_post_message"], resources: ["slack:#ext-partners", "slack:#general"] },
      { tools: ["jira_search", "jira_get_issue", "jira_add_comment"], resources: ["jira:WEB"] },
      { tools: ["runbooks_*"] },
    ],
  },
];

const GROUP_BUNDLES: Array<[string, string]> = [
  ["eng", "engineering"],
  ["eng", "issue-triage"],
  ["eng", "read-only"],
  ["security", "security"],
  ["security", "read-only"],
  ["support", "support-desk"],
  ["support", "read-only"],
];

const USERS = [
  { email: "dana@acme.test", name: "Dana Okafor", groups: ["eng", "security"], admin: false },
  { email: "sam@acme.test", name: "Sam Rivera", groups: ["support"], admin: false },
  { email: "maya@acme.test", name: "Maya Chen", groups: ["eng", "security", "support"], admin: true },
];

/** Idempotent: creates the demo tenant or restores its policy to the shipped defaults. */
export async function seedDemo(): Promise<{ tenantId: string; users: Record<string, string> }> {
  await q(
    `INSERT INTO tenants (slug, name, settings) VALUES ($1, 'Acme Corp', $2)
     ON CONFLICT (slug) DO UPDATE SET settings = excluded.settings`,
    [DEMO_TENANT, JSON.stringify({ labels: DEMO_LABELS })],
  );
  const tenantId = (await q1<{ id: string }>("SELECT id FROM tenants WHERE slug = $1", [DEMO_TENANT]))!.id;

  const pw = await hashPassword(DEMO_PASSWORD);
  const users: Record<string, string> = {};
  for (const u of USERS) {
    const existing = await q1<{ id: string }>("SELECT id FROM users WHERE email = $1", [u.email]);
    if (existing) {
      await q("UPDATE users SET groups = $2, is_admin = $3 WHERE email = $1", [u.email, u.groups, u.admin]);
      users[u.email] = existing.id;
    } else {
      const r = await q1<{ id: string }>(
        "INSERT INTO users (tenant_id, email, display_name, password_hash, is_admin, groups) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id",
        [tenantId, u.email, u.name, pw, u.admin, u.groups],
      );
      users[u.email] = r!.id;
    }
  }

  for (const b of DEMO_BUNDLES) {
    await q("UPSERT INTO bundles (tenant_id, id, name, description, rules, updated_at) VALUES ($1,$2,$3,$4,$5, now())", [
      tenantId,
      b.id,
      b.name,
      b.description,
      JSON.stringify(b.rules),
    ]);
  }
  await q("DELETE FROM group_bundles WHERE tenant_id = $1", [tenantId]);
  for (const [g, b] of GROUP_BUNDLES) await q("INSERT INTO group_bundles (tenant_id, grp, bundle_id) VALUES ($1,$2,$3)", [tenantId, g, b]);

  // Shared connector credentials for the simulated workspace, sealed in the vault.
  const vault = getVault();
  for (const [connector, token] of Object.entries(SIM_TOKENS)) {
    const s = vault.encrypt(token, credentialAad(tenantId, null, connector));
    // NULL user_id never conflicts in a UNIQUE index, so replace the shared row explicitly.
    await q("DELETE FROM credentials WHERE tenant_id = $1 AND user_id IS NULL AND connector = $2", [tenantId, connector]);
    await q(
      `INSERT INTO credentials (tenant_id, user_id, connector, ciphertext, wrapped_key, kek_version, scopes)
       VALUES ($1, NULL, $2, $3, $4, $5, $6)`,
      [tenantId, connector, s.ciphertext, s.wrappedKey, s.kekVersion, ["simulated"]],
    );
  }
  clearPolicyCaches();
  return { tenantId, users };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  migrate()
    .then(() => seedDemo())
    .then((r) => console.log("seeded tenant", r.tenantId))
    .then(() => closeDb())
    .catch((e) => {
      console.error(e);
      process.exit(1);
    });
}
