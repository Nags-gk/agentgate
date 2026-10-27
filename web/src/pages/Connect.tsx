import { useState } from "react";
import { api, ago, type Me } from "../api";
import { Err, Page, useLoad } from "../ui";

interface Creds {
  activeKekVersion: number;
  credentials: Array<{ id: string; connector: string; user_id: string | null; kek_version: string; scopes: string[]; created_at: string; rotated_at: string | null }>;
}

export function Connect({ me }: { me: Me }) {
  const pub = useLoad(() => api<{ mcpUrl: string }>("/public"));
  const creds = useLoad(() => api<Creds>("/credentials"));
  const [rewrap, setRewrap] = useState<string>();
  const url = pub.data?.mcpUrl ?? "";
  return (
    <Page title="Connect an agent" lede="Any MCP client that supports OAuth can connect. It registers itself, sends you to sign in, and you choose which bundle it gets.">
      <Err msg={pub.error ?? creds.error} />
      <section className="panel">
        <h3>Claude Code</h3>
        <pre className="secret" style={{ borderStyle: "solid", borderColor: "var(--line)" }}>{`claude mcp add --transport http agentgate ${url}`}</pre>
        <p className="muted" style={{ marginTop: 8 }}>
          Then run <code>/mcp</code> in Claude Code and choose agentgate to sign in.
        </p>
        <h3 style={{ marginTop: 16 }}>Claude, Cursor and other clients</h3>
        <p>
          Add a remote MCP server with the URL <code>{url}</code>. The client discovers the authorization server from{" "}
          <code>/.well-known/oauth-protected-resource</code> and registers itself.
        </p>
        <h3 style={{ marginTop: 16 }}>Unattended agents</h3>
        <p>
          Create an agent on the Agents page to get a client ID and secret, then exchange them for a 15-minute token with the <code>client_credentials</code> grant.
        </p>
      </section>
      <section className="panel">
        <div className="spread">
          <div>
            <h3>Stored credentials</h3>
            <p className="muted">
              Upstream tokens are sealed with AES-256-GCM under a per-secret data key, which is wrapped by key-encryption key version {creds.data?.activeKekVersion}. Agents
              never receive them.
            </p>
          </div>
          {me.admin && (
            <button
              onClick={async () => {
                const r = await api<{ rewrapped: number; activeKekVersion: number }>("/credentials/rewrap", { method: "POST" });
                setRewrap(`Re-wrapped ${r.rewrapped} data key${r.rewrapped === 1 ? "" : "s"} under version ${r.activeKekVersion}.`);
                creds.reload();
              }}
            >
              Re-wrap under the active key
            </button>
          )}
        </div>
        {rewrap && <div className="note good">{rewrap}</div>}
        <div className="scroll">
          <table>
            <thead>
              <tr>
                <th>Connector</th>
                <th>Owner</th>
                <th>Key version</th>
                <th>Stored</th>
                <th>Last rotated</th>
              </tr>
            </thead>
            <tbody>
              {creds.data?.credentials.map((c) => (
                <tr key={c.id}>
                  <td>{c.connector}</td>
                  <td>{c.user_id ? "personal" : "shared"}</td>
                  <td className="num">{c.kek_version}</td>
                  <td>{ago(c.created_at)}</td>
                  <td>{c.rotated_at ? ago(c.rotated_at) : "never"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </Page>
  );
}
