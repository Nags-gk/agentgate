import { useState } from "react";
import { api, type AuditRow } from "../api";
import { Err, Ledger, Page, useLoad } from "../ui";

interface Verify {
  ok: boolean;
  checked: number;
  firstSeq?: number;
  lastSeq?: number;
  brokenAt?: number;
  problem?: string;
}

export function Activity() {
  const [decision, setDecision] = useState("");
  const [tool, setTool] = useState("");
  const [verify, setVerify] = useState<Verify>();
  const [checking, setChecking] = useState(false);
  const qs = new URLSearchParams({ limit: "100", ...(decision ? { decision } : {}), ...(tool ? { tool } : {}) }).toString();
  const rows = useLoad(() => api<AuditRow[]>(`/audit?${qs}`), [qs]);

  return (
    <Page
      title="Activity"
      lede="Every tool call that reached the gateway, newest first. Each entry is chained to the one before it by a SHA-256 hash, so an edited or deleted entry breaks the chain."
      actions={
        <div className="row">
          <button
            disabled={checking}
            onClick={async () => {
              setChecking(true);
              setVerify(await api<Verify>("/audit/verify").finally(() => setChecking(false)));
            }}
          >
            {checking ? "Checking…" : "Verify the chain"}
          </button>
          <a className="btn" href="/api/audit/export">
            Export NDJSON
          </a>
        </div>
      }
    >
      {verify &&
        (verify.ok ? (
          <div className="note good">
            Chain intact: {verify.checked.toLocaleString()} entries{verify.firstSeq ? ` (#${verify.firstSeq} to #${verify.lastSeq})` : ""} recomputed and linked.
          </div>
        ) : (
          <div className="note bad">
            Chain broken at entry #{verify.brokenAt}: {verify.problem}
          </div>
        ))}
      <div className="row" style={{ margin: "8px 0 16px" }}>
        <label className="field">
          Decision
          <select value={decision} onChange={(e) => setDecision(e.target.value)}>
            <option value="">All</option>
            <option value="allow">Passed</option>
            <option value="deny">Stopped</option>
            <option value="error">Upstream errors</option>
          </select>
        </label>
        <label className="field">
          Tool
          <input placeholder="e.g. slack_post_message" value={tool} onChange={(e) => setTool(e.target.value.trim())} />
        </label>
      </div>
      <Err msg={rows.error} />
      {rows.data && <Ledger rows={rows.data} />}
    </Page>
  );
}
