import { readFile } from "node:fs/promises";
import { q, q1 } from "./db/index.js";
import { runScenario, runSuite } from "./agents/runner.js";
import { SCENARIOS } from "./agents/scenarios.js";

/** Named demo agents and the scenarios each one runs, so a fresh demo has history to look at. */
const DEMO_TRAFFIC: Array<[string, string]> = [
  ["triage-bot", "benign-triage"],
  ["triage-bot", "issue-injection-triage"],
  ["support-helper", "benign-support"],
  ["research-bot", "benign-runbook"],
  ["research-bot", "partner-asks-for-incident"],
  ["incident-scribe", "confidential-to-public-full-role"],
  ["triage-bot", "benign-triage"],
];

export async function bootstrapDemoTraffic(): Promise<void> {
  // Red-team results: run the scripted suite once, and load an LLM report produced in CI if present.
  if (!(await q1("SELECT 1 FROM redteam_runs WHERE agent = 'scripted'"))) await runSuite("scripted");
  try {
    const gem = JSON.parse(await readFile(new URL("../eval/results/gemini.json", import.meta.url), "utf8")) as { agent: string; generatedAt: string };
    if (!(await q1("SELECT 1 FROM redteam_runs WHERE agent = $1 AND created_at = $2", [gem.agent, gem.generatedAt])))
      await q("INSERT INTO redteam_runs (agent, report, created_at) VALUES ($1, $2, $3)", [gem.agent, JSON.stringify(gem), gem.generatedAt]);
  } catch {
    /* no LLM report checked in yet */
  }
  const exists = await q1("SELECT 1 FROM agents WHERE name = 'triage-bot'");
  if (exists) return;
  for (const [agentName, id] of DEMO_TRAFFIC) {
    const s = SCENARIOS.find((x) => x.id === id);
    if (s) await runScenario(s, "gateway", "scripted", { agentName });
  }
  console.log("demo traffic generated");
}
