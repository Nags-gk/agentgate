import { useState } from "react";
import { api, ago, type Me } from "../api";
import { Err, Page, useLoad } from "../ui";

interface AgentRow {
  id: string;
  name: string;
  bundle_id: string;
  disabled: boolean;
  created_at: string;
  owner: string;
  calls: string;
}
interface Radius {
  agent: { id: string; name: string; bundle: string; owner?: string };
  direct: { tools: number; writeTools: number; destructiveTools: string[]; scopes: Record<string, string[]> };
  gateway: { tools: number; writeTools: number; destructiveTools: string[]; detail: Array<{ tool: string; action: string; resources: string[] }> };
  reduction: number;
  usage: Array<{ tool: string; calls: number; denied: number }>;
  unusedGrants: string[];
}
interface Created {
  id: string;
  clientId: string;
  clientSecret: string;
  tokenUrl: string;
  mcpUrl: string;
}

function BlastRadius({ id }: { id: string }) {
  const r = useLoad(() => api<Radius>(`/agents/${id}/blast-radius`), [id]);
  if (r.error) return <Err msg={r.error} />;
  if (!r.data) return null;
  const d = r.data;
  return (
    <div className="panel">
      <h2 style={{ marginTop: 0 }}>If {d.agent.name}'s credential leaked</h2>
      <p className="muted">
        Comparing the agent holding its owner's raw tokens with the same agent behind AgentGate. AgentGate removes {Math.round(d.reduction * 100)}% of the tools an attacker
        could use.
      </p>
      <div className="radius">
        <div className="side raw">
          <div className="count">{d.direct.tools}</div>
          <div>tools with the raw tokens</div>
          <dl>
            <dt>Can write</dt>
            <dd>{d.direct.writeTools} tools</dd>
            <dt>Destructive</dt>
            <dd>{d.direct.destructiveTools.join(", ") || "none"}</dd>
            <dt>Reach</dt>
            <dd>every repo, channel and project the tokens can see</dd>
          </dl>
        </div>
        <div className="side scoped">
          <div className="count">{d.gateway.tools}</div>
          <div>tools through AgentGate</div>
          <dl>
            <dt>Can write</dt>
            <dd>{d.gateway.writeTools} tools</dd>
            <dt>Destructive</dt>
            <dd>{d.gateway.destructiveTools.join(", ") || "none"}</dd>
            <dt>Reach</dt>
            <dd>{[...new Set(d.gateway.detail.flatMap((t) => (t.tool.startsWith("runbooks_") ? ["team runbooks"] : t.resources)))].join(", ") || "none"}</dd>
          </dl>
        </div>
      </div>
      <h3 style={{ marginTop: 18 }}>Granted but never used in 30 days</h3>
      {d.unusedGrants.length ? (
        <p>
          {d.unusedGrants.map((t) => (
            <span className="chip code" key={t}>
              {t}
            </span>
          ))}
          <br />
          <span className="muted">Removing these from bundle {d.agent.bundle} would shrink the blast radius further.</span>
        </p>
      ) : (
        <p className="muted">Every granted tool has been used. The bundle fits the job.</p>
      )}
    </div>
  );
}

export function Agents({ me }: { me: Me }) {
  const [all, setAll] = useState(false);
  const agents = useLoad(() => api<AgentRow[]>(`/agents${all ? "?all=1" : ""}`), [all]);
  const [sel, setSel] = useState<string>();
  const [name, setName] = useState("");
  const [bundle, setBundle] = useState(me.bundles[0] ?? "");
  const [created, setCreated] = useState<Created>();
  const [error, setError] = useState<string>();

  return (
    <Page
      title="Agents"
      lede="Service agents run unattended with client credentials. Each acts for its owner and is capped by both the owner's role and its own bundle."
    >
      <Err msg={agents.error ?? error} />
      <div className="panel">
        <h3>Create an agent</h3>
        <form
          className="row"
          style={{ alignItems: "flex-end" }}
          onSubmit={async (e) => {
            e.preventDefault();
            setError(undefined);
            try {
              setCreated(await api<Created>("/agents", { method: "POST", body: { name, bundle } }));
              setName("");
              agents.reload();
            } catch (err) {
              setError((err as Error).message);
            }
          }}
        >
          <label className="field">
            Name
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="release-notes-bot" required minLength={2} />
          </label>
          <label className="field">
            Bundle
            <select value={bundle} onChange={(e) => setBundle(e.target.value)}>
              {me.bundles.map((b) => (
                <option key={b}>{b}</option>
              ))}
            </select>
          </label>
          <button className="primary">Create agent</button>
        </form>
        {created && (
          <div className="note" style={{ marginTop: 14 }}>
            <p>Copy the secret now; it is shown once and stored only as a hash.</p>
            <div className="secret">
              client_id: {created.clientId}
              <br />
              client_secret: {created.clientSecret}
            </div>
            <p style={{ marginTop: 10, marginBottom: 0 }}>
              Get a token: <code>curl -u {created.clientId}:… -d grant_type=client_credentials {created.tokenUrl}</code>, then call <code>{created.mcpUrl}</code>.
            </p>
          </div>
        )}
      </div>
      <div className="spread" style={{ marginTop: 24 }}>
        <h2 style={{ margin: 0 }}>Agents</h2>
        <label className="row muted" style={{ fontSize: "0.85rem" }}>
          <input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} /> Include evaluation and playground runs
        </label>
      </div>
      <div className="scroll" style={{ marginTop: 8 }}>
        <table>
          <thead>
            <tr>
              <th>Agent</th>
              <th>Owner</th>
              <th>Bundle</th>
              <th className="num">Calls</th>
              <th>Created</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {(agents.data ?? []).map((a) => (
              <tr key={a.id} className="click" onClick={() => setSel(a.id)} aria-selected={sel === a.id}>
                <td>
                  <b>{a.name}</b> {a.disabled && <span className="chip level-restricted">disabled</span>}
                </td>
                <td>{a.owner}</td>
                <td className="mono">{a.bundle_id}</td>
                <td className="num">{a.calls}</td>
                <td>{ago(a.created_at)}</td>
                <td>
                  {!a.disabled && (a.owner === me.email || me.admin) && (
                    <button
                      className="small"
                      onClick={async (e) => {
                        e.stopPropagation();
                        await api(`/agents/${a.id}/disable`, { method: "POST" });
                        agents.reload();
                      }}
                    >
                      Disable
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!agents.data?.length && <p className="muted">No agents yet. Create one above, or tick the box to see agents from evaluation runs.</p>}
      {sel && (
        <div style={{ marginTop: 20 }}>
          <BlastRadius id={sel} />
        </div>
      )}
    </Page>
  );
}
