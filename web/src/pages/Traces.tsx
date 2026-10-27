import { api } from "../api";
import { Err, Page, useLoad } from "../ui";

interface Span {
  traceId: string;
  spanId: string;
  parentId?: string;
  name: string;
  startMs: number;
  durationMs: number;
  status: "ok" | "error";
  attributes: Record<string, unknown>;
}

export function Traces() {
  const d = useLoad(() => api<Span[]>("/traces?limit=600"));
  const traces = new Map<string, Span[]>();
  for (const s of d.data ?? []) traces.set(s.traceId, [...(traces.get(s.traceId) ?? []), s]);
  const list = [...traces.values()]
    .filter((ss) => ss.some((s) => s.name === "gateway.tool_call"))
    .slice(-15)
    .reverse();
  return (
    <Page
      title="Traces"
      lede="OpenTelemetry spans for recent tool calls on this instance: the gateway's own work (policy, guard, audit) against the time spent waiting on GitHub, Slack, Jira or a sandboxed server."
    >
      <Err msg={d.error} />
      {list.map((ss) => {
        const root = ss.find((s) => s.name === "gateway.tool_call")!;
        const t0 = root.startMs;
        const total = Math.max(root.durationMs, 1);
        const upstream = ss.filter((s) => s.name === "upstream.call").reduce((n, s) => n + s.durationMs, 0);
        return (
          <section className="panel" key={root.traceId}>
            <div className="spread">
              <span className="mono">{String(root.attributes.tool)}</span>
              <span className="muted">
                {root.durationMs.toFixed(1)} ms total, {(root.durationMs - upstream).toFixed(1)} ms in the gateway · {String(root.attributes.decision ?? "")}
              </span>
            </div>
            {ss
              .sort((a, b) => a.startMs - b.startMs)
              .map((s) => {
                const left = ((s.startMs - t0) / total) * 100;
                const width = Math.max((s.durationMs / total) * 100, 0.6);
                return (
                  <div className="wf" key={s.spanId} title={`${s.name}: ${s.durationMs.toFixed(2)} ms`}>
                    <div className={`bar${s.status === "error" ? " err" : ""}`} style={{ left: `${left}%`, width: `${width}%` }} />
                    <span className="lbl" style={{ left: `${Math.min(left + width + 0.8, 70)}%` }}>
                      {s.name} {s.durationMs.toFixed(1)} ms
                    </span>
                  </div>
                );
              })}
          </section>
        );
      })}
      {!list.length && <p className="muted">No traces yet on this instance.</p>}
    </Page>
  );
}
