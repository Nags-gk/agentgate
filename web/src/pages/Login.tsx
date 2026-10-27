import { useEffect, useState } from "react";
import { api, type Me } from "../api";
import { Stamp } from "../ui";

interface PublicInfo {
  demo: boolean;
  mcpUrl: string;
  demoAccounts: Array<{ email: string; role: string }>;
  demoPassword?: string;
}

const SAMPLE = [
  { d: "allow", tool: "github_get_issue", res: "acme/website#7", why: "Allowed by the issue-triage bundle." },
  { d: "flag", tool: "github_get_issue", res: "acme/website#7", why: "The issue hides instructions for AI agents. The session is now untrusted." },
  { d: "deny", tool: "slack_post_message", res: "#ext-partners", why: "This agent may only post to #eng." },
  { d: "deny", tool: "github_delete_repo", res: "acme/website", why: "Not in this agent's bundle, and high-risk after flagged content." },
];

export function Login({ onIn }: { onIn: (m: Me) => void }) {
  const [info, setInfo] = useState<PublicInfo>();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    api<PublicInfo>("/public").then(setInfo, () => {});
  }, []);

  async function signIn(e?: string, p?: string) {
    setBusy(true);
    setError(undefined);
    try {
      await api("/login", { method: "POST", body: { email: e ?? email, password: p ?? password } });
      onIn(await api<Me>("/me"));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="gatepage">
      <section className="story">
        <h1>Let agents work without handing them your keys.</h1>
        <p className="lede">
          AgentGate sits between AI agents and your company's tools. Each agent gets only the tools its job needs, never sees a credential, and every call is
          checked, explained and written to a tamper-evident log.
        </p>
        <ul className="ledger sample" aria-label="Example of what the gateway decides">
          {SAMPLE.map((s, i) => (
            <li key={i}>
              <Stamp decision={s.d} />
              <div className="what">
                <span className="tool">{s.tool}</span>
                <span className="res">{s.res}</span>
                <div className="why">{s.why}</div>
              </div>
            </li>
          ))}
        </ul>
        <p className="muted">
          Source and design notes: <a href="https://github.com/Nags-gk/agentgate">github.com/Nags-gk/agentgate</a>
        </p>
      </section>
      <section className="signin">
        <h2 style={{ marginTop: 0 }}>Sign in</h2>
        {info?.demo && (
          <>
            <p className="muted">
              This is a live demo against a simulated GitHub, Slack and Jira. Pick an account; the password for all of them is{" "}
              <code>{info.demoPassword}</code>.
            </p>
            <div className="demo-list">
              {info.demoAccounts.map((a) => (
                <button key={a.email} disabled={busy} onClick={() => signIn(a.email, info.demoPassword)}>
                  {a.email} <span className="role">{a.role}</span>
                </button>
              ))}
            </div>
            <p className="muted" style={{ margin: "8px 0 0" }}>
              Or sign in by hand:
            </p>
          </>
        )}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void signIn();
          }}
          style={{ display: "grid", gap: 10 }}
        >
          <label className="field">
            Email
            <input type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required />
          </label>
          <label className="field">
            Password
            <input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          </label>
          <button className="primary" disabled={busy}>
            Sign in
          </button>
        </form>
        {error && <div className="note bad">{error}</div>}
      </section>
    </div>
  );
}
