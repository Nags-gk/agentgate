import type { Bundle } from "../policy.js";

const esc = (s: unknown) =>
  String(s ?? "").replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]!);

const PASS_THROUGH = ["response_type", "client_id", "redirect_uri", "code_challenge", "code_challenge_method", "state", "resource", "scope"];

const STYLE = `
:root{--bg:#f6f7f9;--card:#fff;--ink:#14161a;--muted:#5d6470;--line:#e2e5ea;--accent:#2f5bea;--accent-ink:#fff;--bad:#c2372d;--chip:#eef1f6}
@media (prefers-color-scheme:dark){:root{--bg:#0e1013;--card:#171a1f;--ink:#e9ecf1;--muted:#9aa3af;--line:#2a2f37;--accent:#6b8cff;--accent-ink:#0b0d10;--bad:#ff7b6e;--chip:#20252c}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;padding:16px}
.card{width:100%;max-width:440px;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:28px}
.brand{display:flex;align-items:center;gap:10px;font-weight:650;margin-bottom:18px}.dot{width:22px;height:22px;border-radius:6px;background:var(--accent)}
h1{font-size:19px;margin:0 0 6px}p{margin:0 0 14px;color:var(--muted)}label{display:block;font-size:13px;font-weight:600;margin:12px 0 6px}
input[type=email],input[type=password]{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:9px;background:var(--bg);color:var(--ink);font:inherit}
.opt{display:block;border:1px solid var(--line);border-radius:10px;padding:10px 12px;margin:8px 0;cursor:pointer}.opt:has(input:checked){border-color:var(--accent);box-shadow:0 0 0 1px var(--accent)}
.opt b{display:block}.opt span{color:var(--muted);font-size:13px}.opt input{margin-right:8px}
.row{display:flex;gap:10px;margin-top:18px}button{flex:1;padding:10px 14px;border-radius:9px;border:1px solid var(--line);background:var(--card);color:var(--ink);font:600 14px system-ui;cursor:pointer}
button.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-ink)}.err{color:var(--bad);font-size:14px;margin:10px 0 0}
.hint{margin-top:16px;padding:10px 12px;border-radius:9px;background:var(--chip);font-size:13px;color:var(--muted)}code{font:12.5px ui-monospace,Menlo,monospace}
.tools{font-size:12.5px;color:var(--muted);margin-top:4px}`;

function shell(title: string, body: string) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><style>${STYLE}</style></head><body><main class="card"><div class="brand"><span class="dot"></span>AgentGate</div>${body}</main></body></html>`;
}

const hidden = (params: Record<string, string | undefined>) =>
  PASS_THROUGH.filter((k) => params[k] !== undefined)
    .map((k) => `<input type="hidden" name="${k}" value="${esc(params[k])}">`)
    .join("");

export function consentPage(o: {
  clientName: string;
  params: Record<string, string | undefined>;
  demo: boolean;
  error?: string;
  user?: { display_name: string; email: string };
  bundles?: Bundle[];
  ticket?: string;
}) {
  if (o.user && o.bundles && o.ticket) {
    const opts = o.bundles.length
      ? o.bundles
          .map(
            (b, i) => `<label class="opt"><input type="radio" name="bundle" value="${esc(b.id)}" ${i === 0 ? "checked" : ""}><b>${esc(b.name)}</b>
<span>${esc(b.description)}</span><div class="tools">${esc(b.rules.flatMap((r) => r.tools).join(", "))}</div></label>`,
          )
          .join("")
      : `<p class="err">Your role has no access levels to grant.</p>`;
    return shell(
      "Allow access",
      `<h1>Allow ${esc(o.clientName)}?</h1><p>Signed in as ${esc(o.user.display_name)}. Pick what this app may do for you. It will never see your GitHub, Slack or Jira credentials.</p>
<form method="post" action="/oauth/authorize">${hidden(o.params)}<input type="hidden" name="ticket" value="${esc(o.ticket)}">${opts}
<div class="row"><button name="decision" value="deny">Deny</button><button class="primary" name="decision" value="allow" ${o.bundles.length ? "" : "disabled"}>Allow</button></div></form>`,
    );
  }
  return shell(
    "Sign in",
    `<h1>Sign in to connect ${esc(o.clientName)}</h1><p>${esc(o.clientName)} wants to use tools through AgentGate.</p>
<form method="post" action="/oauth/authorize">${hidden(o.params)}
<label for="e">Email</label><input id="e" type="email" name="email" autocomplete="username" required value="${esc(o.params.email)}">
<label for="p">Password</label><input id="p" type="password" name="password" autocomplete="current-password" required>
${o.error ? `<p class="err">${esc(o.error)}</p>` : ""}
<div class="row"><button class="primary" type="submit">Continue</button></div></form>
${o.demo ? `<div class="hint">Demo accounts: <code>dana@acme.test</code> (engineer), <code>sam@acme.test</code> (support), password <code>agentgate-demo</code>.</div>` : ""}`,
  );
}

export const errorPage = (msg: string) => shell("Authorization error", `<h1>Can't authorize this request</h1><p>${esc(msg)}</p>`);
