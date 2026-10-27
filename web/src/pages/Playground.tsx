import { useState } from "react";
import { api, type ScenarioResult } from "../api";
import { Err, Page, Stamp, useLoad, CODE_LABEL } from "../ui";

interface ScenarioInfo {
  id: string;
  title: string;
  kind: "attack" | "benign";
  bundle: string;
  owner: string;
  task: string;
}

function Side({ r, gate }: { r?: ScenarioResult; gate: boolean }) {
  return (
    <section className={`side${gate ? " gate" : ""}`} aria-live="polite">
      <h3>{gate ? "Through AgentGate (scoped token)" : "With the user's raw tokens"}</h3>
      {!r ? (
        <p className="muted">Not run yet.</p>
      ) : (
        <>
          <div className="outcome">
            {r.kind === "attack" ? (
              r.attackSucceeded ? (
                <span className="stamp stop big">Breached</span>
              ) : (
                <span className="stamp pass big">Attack held</span>
              )
            ) : r.taskDone ? (
              <span className="stamp pass big">Task done</span>
            ) : (
              <span className="stamp stop big">Task failed</span>
            )}
            {r.kind === "attack" && <span className="muted">{r.taskDone ? "The legitimate task still got done." : "The legitimate task did not finish."}</span>}
          </div>
          {r.error && <div className="note bad">{r.error}</div>}
          <ul className="ledger">
            {r.calls.map((c, i) => (
              <li key={i}>
                <Stamp decision={c.blocked ? "deny" : c.isError ? "error" : c.text.includes("AgentGate notice") ? "flag" : "allow"} />
                <div className="what">
                  <span className="tool">{c.tool}</span>
                  {c.why === "attack" && <span className="chip" style={{ marginLeft: 8, color: "var(--stop)" }}>injected step</span>}
                  <div className="why">
                    {c.blocked ? (
                      (() => {
                        const m = /^Blocked by AgentGate \(([a-z_]+)\): (.*)$/s.exec(c.text);
                        return (
                          <>
                            <b>{CODE_LABEL[m?.[1] ?? ""] ?? "Blocked"}:</b> {m?.[2] ?? c.text}
                          </>
                        );
                      })()
                    ) : (
                      <code>{JSON.stringify(c.args).slice(0, 140)}</code>
                    )}
                  </div>
                </div>
              </li>
            ))}
          </ul>
          <h3 style={{ marginTop: 16 }}>What reached GitHub, Slack and Jira</h3>
          {r.writes.length ? (
            <ul className="writes">
              {r.writes.map((w, i) => (
                <li key={i}>
                  <b>{w.what}</b>
                  {w.detail ? (
                    <div className="muted">
                      <code>{String(typeof w.detail === "string" ? w.detail : JSON.stringify(w.detail)).slice(0, 160)}</code>
                    </div>
                  ) : null}
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted">Nothing was written.</p>
          )}
        </>
      )}
    </section>
  );
}

export function Playground() {
  const list = useLoad(() => api<ScenarioInfo[]>("/playground/scenarios"));
  const [sel, setSel] = useState("issue-injection-triage");
  const [res, setRes] = useState<{ direct?: ScenarioResult; gateway?: ScenarioResult }>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const s = list.data?.find((x) => x.id === sel);

  async function run() {
    setBusy(true);
    setError(undefined);
    setRes({});
    try {
      const direct = await api<ScenarioResult>("/playground/run", { method: "POST", body: { scenario: sel, mode: "direct" } });
      setRes({ direct });
      await new Promise((r) => setTimeout(r, 2100)); // server allows one run every 2 s
      const gateway = await api<ScenarioResult>("/playground/run", { method: "POST", body: { scenario: sel, mode: "gateway" } });
      setRes({ direct, gateway });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Page
      title="Playground"
      lede="Run the same agent twice against a simulated Acme workspace: once holding the user's raw GitHub, Slack and Jira tokens, once through AgentGate. The agent here is scripted to obey every instruction it reads, so this shows what the gateway stops when the model fails completely."
    >
      <Err msg={list.error ?? error} />
      <div className="panel">
        <div className="row" style={{ alignItems: "flex-end" }}>
          <label className="field" style={{ flex: "1 1 320px" }}>
            Scenario
            <select value={sel} onChange={(e) => setSel(e.target.value)}>
              {(list.data ?? []).map((x) => (
                <option key={x.id} value={x.id}>
                  {x.kind === "attack" ? "Attack: " : "Normal work: "}
                  {x.title}
                </option>
              ))}
            </select>
          </label>
          <button className="primary" onClick={run} disabled={busy || !s}>
            {busy ? "Running…" : "Run both"}
          </button>
        </div>
        {s && (
          <p style={{ margin: "12px 0 0" }}>
            <b>Task:</b> {s.task}
            <br />
            <span className="muted">
              Agent owner {s.owner}, granted bundle <code>{s.bundle}</code>.
            </span>
          </p>
        )}
      </div>
      <div className="versus">
        <Side r={res.direct} gate={false} />
        <Side r={res.gateway} gate />
      </div>
    </Page>
  );
}
