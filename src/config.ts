function env(name: string, fallback?: string): string {
  const v = process.env[name] ?? fallback;
  if (v === undefined) throw new Error(`missing environment variable ${name}`);
  return v;
}

const port = Number(env("PORT", "8080"));

export const config = {
  port,
  /** Public base URL; the MCP resource identifier and OAuth issuer derive from it. */
  publicUrl: env("PUBLIC_URL", `http://localhost:${port}`).replace(/\/$/, ""),
  databaseUrl: env("DATABASE_URL", "postgresql://root@localhost:26257/agentgate?sslmode=disable"),
  dbPoolSize: Number(env("DB_POOL_SIZE", "10")),
  /**
   * Key-encryption keys, "version:base64key" pairs separated by commas. The highest version
   * encrypts; older versions still decrypt until rotation finishes. In production these come
   * from Secret Manager.
   */
  keks: env("VAULT_KEKS", "1:" + Buffer.alloc(32, 7).toString("base64")),
  accessTokenTtlSec: Number(env("ACCESS_TOKEN_TTL", "900")),
  refreshTokenTtlSec: Number(env("REFRESH_TOKEN_TTL", String(30 * 86400))),
  /** Demo mode: seeded tenant, simulated GitHub/Slack/Jira backends, login hints on the page. */
  demo: env("DEMO_MODE", "true") === "true",
  geminiApiKey: process.env.GEMINI_API_KEY,
  rateLimitPerMin: Number(env("RATE_LIMIT_PER_MIN", "120")),
  toolTimeoutMs: Number(env("TOOL_TIMEOUT_MS", "15000")),
};

export const resourceUrl = () => `${config.publicUrl}/mcp`;
