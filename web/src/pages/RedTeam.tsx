import { api, type ScenarioResult } from "../api";
import { Err, Page, useLoad } from "../ui";

interface Report {
  agent: string;
  generatedAt: string;
  results: ScenarioResult[];
  summary: Record<"direct" | "gateway", { attacks: number; attacksSucceeded: number; tasksDoneUnderAttack: number; benign: number; benignDone: number; blockedCalls: number }>;
}

function ReportView({ r }: { r: Report }) {
  const ids = [...new Set(r.results.map((x) => x.scenario))];
  const cell = (id: string, mode: "direct" | "gateway") => {
    const x = r.results.find((y) => y.scenario === id && y.mode === mode);
    if (!x) return <td />;
    if (x.error) return <td className="muted">error: {x.error.slice(0, 60)}</td>;
    if (x.kind === "attack")
      return (
        <td>
          {x.attackSucceeded ? <span className="stamp stop">Breached</span> : <span className="stamp pass">Held</span>}{" "}
          <span className="muted" style={{ fontSize: "0.82rem" }}>
            {x.taskDone ? "task done" : "task lost"}
          </span>
        </td>
      );
    return <td>{x.taskDone ? <span className="stamp pass">Done</span> : <span className="stamp stop">Not done</span>}</td>;
  };
  const s = r.summary;
  return (
    <section className="panel">
      <h2 style={{ marginTop: 0 }}>{r.agent.startsWith("gemini") ? `LLM agent (${r.agent.replace("gemini:", "")})` : "Worst-case scripted agent"}</h2>
      <p>
        With raw tokens, <b>{s.direct.attacksSucceeded}</b> of {s.direct.attacks} attacks succeeded. Through AgentGate, <b>{s.gateway.attacksSucceeded}</b> of{" "}
        {s.gateway.attacks} did, while {s.gateway.benignDone} of {s.gateway.benign} normal tasks still completed and {s.gateway.tasksDoneUnderAttack} of {s.gateway.attacks}{" "}
        attacked tasks were still finished. <span className="muted">Run {new Date(r.generatedAt).toLocaleString()}.</span>
      </p>
      <div className="scroll">
        <table>
          <thead>
            <tr>
              <th>Scenario</th>
              <th>Raw tokens</th>
              <th>Through AgentGate</th>
            </tr>
          </thead>
          <tbody>
            {ids.map((id) => (
              <tr key={id}>
                <td>{r.results.find((x) => x.scenario === id)!.title}</td>
                {cell(id, "direct")}
                {cell(id, "gateway")}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export function RedTeam() {
  const d = useLoad(() => api<Array<{ agent: string; report: Report }>>("/redteam"));
  return (
    <Page
      title="Red team"
      lede="The same scenarios run twice: once with the agent holding raw upstream tokens, once through the gateway. The scripted agent obeys every injected instruction (the worst case); the LLM run shows what a real model does with the same inputs."
    >
      <Err msg={d.error} />
      {d.data?.length ? d.data.map((x) => <ReportView key={x.agent} r={x.report} />) : <p className="muted">No evaluation runs recorded yet.</p>}
    </Page>
  );
}
