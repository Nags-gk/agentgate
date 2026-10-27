import { api, type AuditRow } from "../api";
import { Err, Ledger, Page, navigate, useLoad } from "../ui";

interface OverviewData {
  totals: Array<{ decision: string; n: string }>;
  byTool: Array<{ tool: string; allowed: string; denied: string }>;
  timeline: Array<{ hour: string; allowed: string; denied: string }>;
  agents: number;
  liveSessions: number;
  connectors: Array<{ id: string; name: string; tools: number }>;
}

function Timeline({ data }: { data: OverviewData["timeline"] }) {
  // 24 hourly buckets ending now, empty hours included.
  const now = new Date();
  now.setMinutes(0, 0, 0);
  const hours = Array.from({ length: 24 }, (_, i) => new Date(now.getTime() - (23 - i) * 3600_000));
  const byHour = new Map(data.map((d) => [new Date(d.hour).getTime(), d]));
  const max = Math.max(1, ...data.map((d) => Number(d.allowed) + Number(d.denied)));
  return (
    <div>
      <div className="bars" role="img" aria-label="Tool calls per hour over the last 24 hours, passed and stopped">
        {hours.map((h) => {
          const d = byHour.get(h.getTime());
          const a = Number(d?.allowed ?? 0);
          const s = Number(d?.denied ?? 0);
          return (
            <div className="col" key={h.getTime()} title={`${h.toLocaleTimeString([], { hour: "2-digit" })}: ${a} passed, ${s} stopped`}>
              {a > 0 && <div className="a" style={{ height: `${(a / max) * 110}px` }} />}
              {s > 0 && <div className="d" style={{ height: `${(s / max) * 110}px` }} />}
            </div>
          );
        })}
      </div>
      <div className="axis">
        <span>24 hours ago</span>
        <span>now</span>
      </div>
    </div>
  );
}

export function Overview() {
  const o = useLoad(() => api<OverviewData>("/overview"));
  const recent = useLoad(() => api<AuditRow[]>("/audit?limit=12"));
  const total = (o.data?.totals ?? []).reduce((n, t) => n + Number(t.n), 0);
  const stopped = Number(o.data?.totals.find((t) => t.decision === "deny")?.n ?? 0);

  return (
    <Page title="Overview">
      <Err msg={o.error ?? recent.error} />
      {o.data && (
        <p className="summary">
          {total === 0 ? (
            <>No agent has called a tool this week. Try the Playground to send a scripted agent through the gateway.</>
          ) : (
            <>
              In the last 7 days, agents made <b>{total.toLocaleString()}</b> tool calls. The gateway passed <b className="s-pass">{(total - stopped).toLocaleString()}</b> and stopped{" "}
              <b className="s-stop">{stopped.toLocaleString()}</b>, across {o.data.agents} active agent{o.data.agents === 1 ? "" : "s"} and {o.data.liveSessions} open session
              {o.data.liveSessions === 1 ? "" : "s"}.
            </>
          )}
        </p>
      )}
      <div className="split">
        <div className="panel">
          <h3>Calls per hour</h3>
          {o.data && <Timeline data={o.data.timeline} />}
        </div>
        <div className="panel">
          <h3>Most-used tools this week</h3>
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>Tool</th>
                  <th className="num">Passed</th>
                  <th className="num">Stopped</th>
                </tr>
              </thead>
              <tbody>
                {(o.data?.byTool ?? []).slice(0, 7).map((t) => (
                  <tr key={t.tool}>
                    <td className="mono">{t.tool}</td>
                    <td className="num">{t.allowed}</td>
                    <td className="num">{Number(t.denied) ? <b style={{ color: "var(--stop)" }}>{t.denied}</b> : 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
      <div className="spread" style={{ marginTop: 28 }}>
        <h2 style={{ margin: 0 }}>Latest decisions</h2>
        <button className="small" onClick={() => navigate("/activity")}>
          Open the full log
        </button>
      </div>
      <div style={{ marginTop: 10 }}>{recent.data && <Ledger rows={recent.data} />}</div>
    </Page>
  );
}
