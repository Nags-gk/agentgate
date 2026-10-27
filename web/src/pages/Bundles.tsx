import { useState } from "react";
import { api, type Me } from "../api";
import { Err, Page, useLoad } from "../ui";

interface Rule {
  tools: string[];
  resources?: string[];
  args?: Record<string, { in?: Array<string | number>; maxLength?: number }>;
}
interface BundleRow {
  id: string;
  name: string;
  description: string;
  rules: Rule[];
  updated_at: string;
}
interface Data {
  bundles: BundleRow[];
  groups: Array<{ grp: string; bundle_id: string }>;
  tools: Array<{ name: string; action: string; risk: string }>;
}

const sentence = (r: Rule) => {
  const where = r.resources?.length ? ` on ${r.resources.map((x) => x.replace(/^[a-z]+:/, "")).join(", ")}` : " on any resource the role allows";
  const lim = Object.entries(r.args ?? {})
    .map(([k, v]) => (v.maxLength ? `${k} up to ${v.maxLength} characters` : v.in ? `${k} in ${v.in.join(", ")}` : ""))
    .filter(Boolean);
  return (
    <>
      {r.tools.map((t) => (
        <span className="chip code" key={t}>
          {t}
        </span>
      ))}
      <span className="muted">
        {where}
        {lim.length ? `, with ${lim.join("; ")}` : ""}
      </span>
    </>
  );
};

function Editor({ b, onSaved }: { b: BundleRow; onSaved: () => void }) {
  const [text, setText] = useState(JSON.stringify({ name: b.name, description: b.description, rules: b.rules }, null, 2));
  const [msg, setMsg] = useState<{ ok: boolean; text: string }>();
  return (
    <div style={{ marginTop: 12 }}>
      <textarea value={text} onChange={(e) => setText(e.target.value)} aria-label={`Rules for ${b.id}`} spellCheck={false} />
      <div className="row" style={{ marginTop: 8 }}>
        <button
          className="primary"
          onClick={async () => {
            try {
              await api(`/bundles/${b.id}`, { method: "PUT", body: JSON.parse(text) });
              setMsg({ ok: true, text: "Saved. Connected agents get the new tool list on their next request." });
              onSaved();
            } catch (e) {
              setMsg({ ok: false, text: (e as Error).message });
            }
          }}
        >
          Save bundle
        </button>
        {msg && <span style={{ color: msg.ok ? "var(--pass)" : "var(--stop)" }}>{msg.text}</span>}
      </div>
    </div>
  );
}

export function Bundles({ me }: { me: Me }) {
  const d = useLoad(() => api<Data>("/bundles"));
  const [editing, setEditing] = useState<string>();
  return (
    <Page
      title="Access bundles"
      lede="A bundle is a virtual MCP server: the tools an agent may use, on which resources, with which argument limits. A call passes only if both the user's role and the token's bundle allow it."
    >
      <Err msg={d.error} />
      {d.data?.bundles.map((b) => (
        <section className="panel" key={b.id}>
          <div className="spread">
            <div>
              <h3 style={{ marginBottom: 2 }}>
                {b.name} <span className="muted mono">{b.id}</span>
              </h3>
              <p className="muted" style={{ marginBottom: 6 }}>
                {b.description}
              </p>
              <p style={{ marginBottom: 6 }}>
                Granted to:{" "}
                {d.data!.groups
                  .filter((g) => g.bundle_id === b.id)
                  .map((g) => (
                    <span className="chip" key={g.grp}>
                      {g.grp}
                    </span>
                  ))}
              </p>
            </div>
            {me.admin && (
              <button className="small" onClick={() => setEditing(editing === b.id ? undefined : b.id)}>
                {editing === b.id ? "Close editor" : "Edit rules"}
              </button>
            )}
          </div>
          <ul style={{ paddingLeft: 18, margin: 0 }}>
            {b.rules.map((r, i) => (
              <li key={i} style={{ margin: "4px 0" }}>
                {sentence(r)}
              </li>
            ))}
          </ul>
          {editing === b.id && <Editor b={b} onSaved={d.reload} />}
        </section>
      ))}
    </Page>
  );
}
