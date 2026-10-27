import { useEffect, useState, type ReactNode } from "react";
import { ago, type AuditRow } from "./api";

export function useLoad<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<string>();
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let live = true;
    setError(undefined);
    fn()
      .then((d) => live && setData(d))
      .catch((e: Error) => live && setError(e.message));
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);
  return { data, error, reload: () => setTick((t) => t + 1) };
}

export function Stamp({ decision, code, big }: { decision: string; code?: string; big?: boolean }) {
  const cls = decision === "allow" ? "pass" : decision === "deny" ? "stop" : decision === "flag" ? "flag" : "plain";
  const label = decision === "allow" ? "Passed" : decision === "deny" ? "Stopped" : decision === "flag" ? "Flagged" : decision === "error" ? "Upstream error" : decision;
  return (
    <span className={`stamp ${cls}${big ? " big" : ""}`} title={code}>
      {label}
    </span>
  );
}

export const Level = ({ level }: { level: string | number }) => {
  const name = typeof level === "number" ? ["public", "internal", "confidential", "restricted"][level] ?? "internal" : level;
  return <span className={`chip level-${name}`}>{name}</span>;
};

/** Plain-language reason: strip the code prefix the gateway stores ("flow: ..."). */
export const why = (reason: string) => {
  const m = /^(policy|flow|untrusted|secret|rate_limit): (.*)$/.exec(reason);
  return m ? { code: m[1]!, text: m[2]! } : { code: "", text: reason };
};

export const CODE_LABEL: Record<string, string> = {
  policy: "Outside this agent's access",
  flow: "Data-flow rule",
  untrusted: "After a prompt injection",
  secret: "Credential in arguments",
  rate_limit: "Rate limit",
};

export function LedgerRow({ row, open, onToggle }: { row: AuditRow; open: boolean; onToggle: () => void }) {
  const r = why(row.reason);
  const flagged = row.findings?.some((f) => f.kind === "injection");
  const redacted = row.findings?.filter((f) => f.kind === "secret").length ?? 0;
  const res = row.args_redacted?._resource as string | undefined;
  return (
    <li>
      <Stamp decision={row.decision === "allow" && flagged ? "flag" : row.decision} code={r.code} />
      <div className="what">
        <button className="small" style={{ all: "unset", cursor: "pointer" }} onClick={onToggle} aria-expanded={open}>
          <span className="tool">{row.tool}</span>
          {res && <span className="res">{res.replace(/^[a-z]+:/, "")}</span>}
        </button>
        <div className="why">
          {row.decision === "deny" ? (
            <>
              <b>{CODE_LABEL[r.code] ?? r.code}:</b> {r.text}
            </>
          ) : row.decision === "error" ? (
            r.text
          ) : flagged ? (
            "Result contained instructions aimed at the agent; marked as untrusted."
          ) : redacted ? (
            `${redacted} secret${redacted > 1 ? "s" : ""} redacted before the agent saw the result.`
          ) : (
            <span className="muted">Allowed by bundle {row.bundle_id}</span>
          )}
          <span className="muted"> · {ago(row.ts)}</span>
        </div>
        {open && (
          <div className="detail">
            <pre>
              {JSON.stringify(
                { seq: Number(row.seq), args: row.args_redacted, findings: row.findings, flow: row.flow, latency_ms: Number(row.latency_ms), session: row.session_id, agent: row.agent_id, client: row.client_id, trace: row.trace_id, hash: row.hash, prev_hash: row.prev_hash },
                null,
                1,
              )}
            </pre>
          </div>
        )}
      </div>
    </li>
  );
}

export function Ledger({ rows }: { rows: AuditRow[] }) {
  const [open, setOpen] = useState<string>();
  if (!rows.length) return <p className="muted">No tool calls yet. Run a scenario in the Playground or connect an agent.</p>;
  return (
    <ul className="ledger">
      {rows.map((r) => (
        <LedgerRow key={r.seq} row={r} open={open === r.seq} onToggle={() => setOpen(open === r.seq ? undefined : r.seq)} />
      ))}
    </ul>
  );
}

export const Err = ({ msg }: { msg?: string }) => (msg ? <div className="note bad">{msg}</div> : null);

export function Page({ title, lede, children, actions }: { title: string; lede?: ReactNode; children: ReactNode; actions?: ReactNode }) {
  return (
    <main className="page">
      <div className="spread">
        <div>
          <h1>{title}</h1>
          {lede && <p className="lede">{lede}</p>}
        </div>
        {actions}
      </div>
      {children}
    </main>
  );
}

export function navigate(path: string) {
  history.pushState(null, "", path);
  window.dispatchEvent(new PopStateEvent("popstate"));
}
