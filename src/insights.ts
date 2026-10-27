import { q, q1 } from "./db/index.js";
import { bundleMentions, type Bundle } from "./policy.js";
import { getBundle, getUser, userBundles } from "./principals.js";
import { connectors } from "./gateway/registry.js";

/**
 * Blast radius: what an agent could do if its credential leaked, with and without AgentGate.
 *  direct  = the agent holds the owner's raw upstream tokens: every tool of every connected
 *            system, on every resource the token reaches
 *  gateway = tools in (agent bundle AND owner ceiling), limited to the bundle's resources
 *  used    = what it actually called in the last 30 days, from the audit log
 * Granted-but-unused tools are suggested for removal (least privilege from evidence).
 */
export async function blastRadius(tenantId: string, agentId: string) {
  const agent = await q1<{ id: string; name: string; owner_user_id: string; bundle_id: string }>(
    "SELECT id, name, owner_user_id, bundle_id FROM agents WHERE tenant_id = $1 AND id = $2",
    [tenantId, agentId],
  );
  if (!agent) return undefined;
  const owner = await getUser(tenantId, agent.owner_user_id);
  const grant = await getBundle(tenantId, agent.bundle_id);
  const ceiling = owner ? await userBundles(tenantId, owner.groups) : [];
  const creds = await q<{ connector: string }>("SELECT DISTINCT connector FROM credentials WHERE tenant_id = $1", [tenantId]);
  const connected = new Set(creds.map((c) => c.connector));

  const direct = connectors
    .filter((c) => connected.has(c.id))
    .flatMap((c) => c.tools.map((t) => ({ tool: t.name, connector: c.id, action: t.action, risk: t.risk, scopes: c.directTokenScopes })));
  const gatewayTools = grant
    ? connectors
        .flatMap((c) => c.tools)
        .filter((t) => bundleMentions(grant, t.name) && ceiling.some((b) => bundleMentions(b, t.name)))
        .map((t) => ({ tool: t.name, action: t.action, risk: t.risk, resources: resourcesFor(grant, t.name) }))
    : [];

  const used = await q<{ tool: string; calls: string; denied: string }>(
    `SELECT tool, count(*) AS calls, count(*) FILTER (WHERE decision = 'deny') AS denied FROM audit_events
     WHERE tenant_id = $1 AND agent_id = $2 AND ts > now() - INTERVAL '30 days' GROUP BY tool ORDER BY calls DESC`,
    [tenantId, agentId],
  );
  const usedOk = new Set(used.filter((u) => Number(u.calls) > Number(u.denied)).map((u) => u.tool));
  const unused = gatewayTools.filter((t) => !usedOk.has(t.tool)).map((t) => t.tool);

  return {
    agent: { id: agent.id, name: agent.name, bundle: agent.bundle_id, owner: owner?.email },
    direct: {
      tools: direct.length,
      writeTools: direct.filter((t) => t.action === "write").length,
      destructiveTools: direct.filter((t) => t.risk === "high").map((t) => t.tool),
      scopes: Object.fromEntries(connectors.filter((c) => connected.has(c.id)).map((c) => [c.id, c.directTokenScopes])),
      resources: "every resource the token can reach",
    },
    gateway: {
      tools: gatewayTools.length,
      writeTools: gatewayTools.filter((t) => t.action === "write").length,
      destructiveTools: gatewayTools.filter((t) => t.risk === "high").map((t) => t.tool),
      detail: gatewayTools,
    },
    reduction: direct.length ? 1 - gatewayTools.length / direct.length : 0,
    usage: used.map((u) => ({ tool: u.tool, calls: Number(u.calls), denied: Number(u.denied) })),
    unusedGrants: unused,
  };
}

function resourcesFor(b: Bundle, tool: string): string[] {
  const rs = b.rules.filter((r) => r.tools.some((t) => new RegExp("^" + t.replace(/\*/g, ".*") + "$").test(tool)));
  if (rs.some((r) => !r.resources?.length)) return ["*"];
  return [...new Set(rs.flatMap((r) => r.resources ?? []))];
}
