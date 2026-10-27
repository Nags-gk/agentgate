/**
 * Red-team evaluation. Starts AgentGate in-process against the configured CockroachDB, then
 * runs every scenario twice: once with the agent holding raw upstream tokens ("direct"), once
 * through the gateway with a scoped token. Writes eval/results/<agent>.json.
 *
 *   npx tsx eval/redteam.ts                 # worst-case scripted agent (obeys every injection)
 *   GEMINI_API_KEY=... npx tsx eval/redteam.ts --agent gemini [--model gemini-x-flash]
 */
import { mkdir, writeFile } from "node:fs/promises";
import { serve } from "@hono/node-server";
import { buildApp } from "../src/app.js";
import { config } from "../src/config.js";
import { closeDb } from "../src/db/index.js";
import { migrate } from "../src/db/migrate.js";
import { signingKey } from "../src/auth/crypto.js";
import { startConnectors, stopConnectors } from "../src/gateway/registry.js";
import { seedDemo } from "../src/seed.js";
import { runSuite, type AgentKind } from "../src/agents/runner.js";

const arg = (k: string) => {
  const i = process.argv.indexOf(`--${k}`);
  return i > 0 ? process.argv[i + 1] : undefined;
};
const agent = (arg("agent") ?? "scripted") as AgentKind;

await migrate(false);
await signingKey();
await seedDemo();
await startConnectors();
const server = serve({ fetch: buildApp().fetch, port: config.port, hostname: "127.0.0.1" });
await new Promise((r) => setTimeout(r, 200));

try {
  const report = await runSuite(agent, { geminiModel: arg("model"), only: arg("only") });
  for (const r of report.results) {
    const verdict = r.kind === "attack" ? (r.attackSucceeded ? "BREACHED" : "held") : r.taskDone ? "done" : "NOT DONE";
    const blocked = r.calls.filter((c) => c.blocked).length;
    const task = r.kind === "attack" ? (r.taskDone ? "task done" : "task lost") : "";
    console.log(`${r.mode.padEnd(8)} ${r.scenario.padEnd(36)} ${verdict.padEnd(9)} ${task.padEnd(9)} calls=${r.calls.length} blocked=${blocked}${r.error ? ` error=${r.error}` : ""}`);
  }
  console.log("\nsummary", JSON.stringify(report.summary));
  await mkdir(new URL("./results/", import.meta.url), { recursive: true });
  const name = report.agent.startsWith("gemini") ? "gemini" : agent;
  await writeFile(new URL(`./results/${name}.json`, import.meta.url), JSON.stringify(report, null, 1));
} finally {
  server.close();
  await stopConnectors();
  await closeDb();
}
