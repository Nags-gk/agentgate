import { config, resourceUrl } from "../config.js";
import { q, q1 } from "../db/index.js";
import { issueAccessToken } from "../auth/tokens.js";
import { resetSims, sim, simLeaks } from "../sim/index.js";
import { redactSecrets } from "../guard/scan.js";
import { DirectProvider, GatewayProvider, type ToolProvider } from "./providers.js";
import { runGeminiAgent } from "./gemini.js";
import { SCENARIOS, type CallLog, type Scenario } from "./scenarios.js";

export type Mode = "gateway" | "direct";
export type AgentKind = "scripted" | "gemini";

export interface ScenarioResult {
  scenario: string;
  title: string;
  kind: Scenario["kind"];
  mode: Mode;
  agent: string;
  attackSucceeded: boolean | null;
  taskDone: boolean;
  calls: Array<CallLog & { blocked: boolean }>;
  writes: typeof sim.writes;
  finalText?: string;
  error?: string;
}

/**
 * A service agent for one run, so its calls appear under its own name in the audit log.
 * Named agents (demo traffic) are reused; ephemeral ones are disabled when the run ends.
 */
async function agentFor(s: Scenario, opts: { runLabel?: string; agentName?: string }): Promise<{ id: string; token: string; ephemeral: boolean }> {
  const owner = await q1<{ tenant_id: string; id: string }>("SELECT tenant_id, id FROM users WHERE email = $1", [s.owner]);
  if (!owner) throw new Error(`owner ${s.owner} not found; seed the demo tenant first`);
  let agent = opts.agentName
    ? await q1<{ id: string }>("SELECT id FROM agents WHERE tenant_id = $1 AND name = $2 AND bundle_id = $3 AND NOT disabled", [owner.tenant_id, opts.agentName, s.bundle])
    : undefined;
  agent ??= await q1<{ id: string }>("INSERT INTO agents (tenant_id, name, owner_user_id, bundle_id) VALUES ($1,$2,$3,$4) RETURNING id", [
    owner.tenant_id,
    (opts.agentName ?? `${opts.runLabel ?? "run"}:${s.id}`).slice(0, 80),
    owner.id,
    s.bundle,
  ]);
  const token = await issueAccessToken({ sub: owner.id, aud: resourceUrl(), tid: owner.tenant_id, bid: s.bundle, cid: "agentgate-eval", fam: agent!.id, agt: agent!.id });
  return { id: agent!.id, token, ephemeral: !opts.agentName };
}

let running: Promise<unknown> = Promise.resolve();

/** Runs are serialized because they share the simulated workspace. */
export function runScenario(s: Scenario, mode: Mode, agent: AgentKind, opts: { geminiModel?: string; runLabel?: string; agentName?: string } = {}): Promise<ScenarioResult> {
  const next = running.catch(() => {}).then(() => runScenarioNow(s, mode, agent, opts));
  running = next;
  return next;
}

async function runScenarioNow(s: Scenario, mode: Mode, agent: AgentKind, opts: { geminiModel?: string; runLabel?: string; agentName?: string }): Promise<ScenarioResult> {
  resetSims();
  let provider: ToolProvider | undefined;
  const calls: CallLog[] = [];
  let finalText: string | undefined;
  let agentLabel = agent as string;
  let svc: Awaited<ReturnType<typeof agentFor>> | undefined;
  try {
    if (mode === "gateway") {
      svc = await agentFor(s, opts);
      provider = await GatewayProvider.connect(`http://127.0.0.1:${config.port}/mcp`, svc.token);
    } else provider = new DirectProvider(`http://127.0.0.1:${config.port}/sim`);
    if (agent === "scripted") {
      for (const step of s.scripted) {
        const r = await provider.call(step.tool, step.args);
        calls.push({ ...step, isError: r.isError, text: r.text.slice(0, 2000) });
      }
    } else {
      if (!config.geminiApiKey) throw new Error("GEMINI_API_KEY is not set");
      const run = await runGeminiAgent(provider, s.task, { apiKey: config.geminiApiKey, model: opts.geminiModel });
      calls.push(...run.calls);
      finalText = run.finalText;
      agentLabel = `gemini:${run.model}`;
    }
  } catch (e) {
    return result(s, mode, agentLabel, calls, finalText, (e as Error).message);
  } finally {
    await provider?.close().catch(() => {});
    if (svc?.ephemeral) await q("UPDATE agents SET disabled = true WHERE id = $1", [svc.id]).catch(() => {});
  }
  return result(s, mode, agentLabel, calls, finalText);
}

function result(s: Scenario, mode: Mode, agent: string, calls: CallLog[], finalText?: string, error?: string): ScenarioResult {
  const state = sim;
  return {
    scenario: s.id,
    title: s.title,
    kind: s.kind,
    mode,
    agent,
    attackSucceeded: s.kind === "attack" ? !!s.attackSucceeded?.(state, calls) : null,
    taskDone: s.taskDone(state),
    calls: calls.map((c) => ({ ...c, blocked: c.isError && c.text.startsWith("Blocked by AgentGate") })),
    writes: [...state.writes],
    finalText,
    error,
  };
}

export interface Report {
  agent: string;
  generatedAt: string;
  results: ScenarioResult[];
  summary: Record<Mode, { attacks: number; attacksSucceeded: number; tasksDoneUnderAttack: number; benign: number; benignDone: number; blockedCalls: number }>;
  leaks: ReturnType<typeof simLeaks>;
}

export async function runSuite(agent: AgentKind, opts: { geminiModel?: string; only?: string } = {}): Promise<Report> {
  const results: ScenarioResult[] = [];
  for (const s of SCENARIOS.filter((x) => !opts.only || x.id.includes(opts.only))) {
    for (const mode of ["direct", "gateway"] as const) {
      results.push(await runScenario(s, mode, agent, { ...opts, runLabel: `eval-${agent}` }));
    }
  }
  const summary = {} as Report["summary"];
  for (const mode of ["direct", "gateway"] as const) {
    const rs = results.filter((r) => r.mode === mode);
    summary[mode] = {
      attacks: rs.filter((r) => r.kind === "attack").length,
      attacksSucceeded: rs.filter((r) => r.attackSucceeded).length,
      tasksDoneUnderAttack: rs.filter((r) => r.kind === "attack" && r.taskDone).length,
      benign: rs.filter((r) => r.kind === "benign").length,
      benignDone: rs.filter((r) => r.kind === "benign" && r.taskDone).length,
      blockedCalls: rs.reduce((n, r) => n + r.calls.filter((c) => c.blocked).length, 0),
    };
  }
  // Stored reports keep verdicts but not the planted secrets themselves.
  const report = redactSecrets({ agent: results[0]?.agent ?? agent, generatedAt: new Date().toISOString(), results, summary, leaks: simLeaks() })
    .value as Report;
  await q("INSERT INTO redteam_runs (agent, report) VALUES ($1, $2)", [report.agent, JSON.stringify(report)]);
  resetSims();
  return report;
}
