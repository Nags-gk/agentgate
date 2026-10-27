import { config } from "../config.js";
import { q1 } from "../db/index.js";
import { tenantSettings } from "../principals.js";
import { cache } from "../cache.js";
import { github } from "../connectors/github.js";
import { jira } from "../connectors/jira.js";
import { SandboxedConnector } from "../connectors/sandbox.js";
import { slackConnector } from "../connectors/slack.js";
import type { Connector, ToolDef } from "../connectors/types.js";
import { getVault } from "../vault.js";

const REAL_BASE: Record<string, string> = {
  github: "https://api.github.com",
  slack: "https://slack.com",
};

export const runbooks = new SandboxedConnector({
  id: "runbooks",
  name: "Runbooks",
  description: "Team runbooks, served by a third-party-style MCP server running in the sandbox.",
  entry: "server.mjs",
  egress: [],
});

export const connectors: Connector[] = [github, slackConnector, jira, runbooks];

export function connectorFor(tool: string): Connector | undefined {
  return connectors.find((c) => tool.startsWith(`${c.id}_`));
}

export function allTools(): ToolDef[] {
  return connectors.flatMap((c) => c.tools);
}

export async function startConnectors(): Promise<void> {
  await runbooks.start().catch((e) => console.error("runbooks sandbox failed to start:", (e as Error).message));
}

export async function stopConnectors(): Promise<void> {
  await runbooks.stop();
}

/** Upstream base URL: the built-in simulator in demo mode, else the real API (Jira is per-site). */
export async function baseUrlFor(tenantId: string, connectorId: string): Promise<string> {
  const configured = (await tenantSettings(tenantId)).connectors?.[connectorId]?.baseUrl;
  if (configured) return configured;
  if (config.demo) return `http://127.0.0.1:${config.port}/sim/${connectorId}`;
  return REAL_BASE[connectorId] ?? "";
}

/** The user's own credential for a connector, else the tenant's shared one. Decrypted per call. */
// Only sealed rows are cached (5 s); plaintext exists in memory just for the duration of a call.
type SealedRow = { user_id: string | null; ciphertext: Buffer; wrapped_key: Buffer; kek_version: string } | undefined;
const sealedCache = cache<SealedRow>();

export async function credentialFor(tenantId: string, userId: string, connectorId: string): Promise<string | undefined> {
  const row = await sealedCache.get(`${tenantId}:${userId}:${connectorId}`, () => sealedRow(tenantId, userId, connectorId));
  if (!row) return undefined;
  return getVault().decrypt(
    { ciphertext: row.ciphertext, wrappedKey: row.wrapped_key, kekVersion: Number(row.kek_version) },
    credentialAad(tenantId, row.user_id, connectorId),
  );
}

async function sealedRow(tenantId: string, userId: string, connectorId: string): Promise<SealedRow> {
  return q1<{ user_id: string | null; ciphertext: Buffer; wrapped_key: Buffer; kek_version: string }>(
    `SELECT user_id, ciphertext, wrapped_key, kek_version FROM credentials
     WHERE tenant_id = $1 AND connector = $2 AND (user_id = $3 OR user_id IS NULL)
     ORDER BY user_id IS NULL LIMIT 1`,
    [tenantId, connectorId, userId],
  );
}

export const credentialAad = (tenantId: string, userId: string | null, connector: string) => `cred:${tenantId}:${userId ?? "shared"}:${connector}`;
