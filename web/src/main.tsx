import { StrictMode, useEffect, useState, type ReactElement } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";
import { api, type Me } from "./api";
import { navigate } from "./ui";
import { Login } from "./pages/Login";
import { Overview } from "./pages/Overview";
import { Activity } from "./pages/Activity";
import { Agents } from "./pages/Agents";
import { Bundles } from "./pages/Bundles";
import { Sessions } from "./pages/Sessions";
import { RedTeam } from "./pages/RedTeam";
import { Playground } from "./pages/Playground";
import { Connect } from "./pages/Connect";
import { Traces } from "./pages/Traces";

const ROUTES: Array<{ path: string; label: string; el: (me: Me) => ReactElement; group?: number }> = [
  { path: "/", label: "Overview", el: () => <Overview /> },
  { path: "/playground", label: "Playground", el: () => <Playground /> },
  { path: "/activity", label: "Activity", el: () => <Activity /> },
  { path: "/agents", label: "Agents", el: (me) => <Agents me={me} /> },
  { path: "/bundles", label: "Access bundles", el: (me) => <Bundles me={me} /> },
  { path: "/sessions", label: "Sessions", el: () => <Sessions />, group: 1 },
  { path: "/redteam", label: "Red team", el: () => <RedTeam />, group: 1 },
  { path: "/traces", label: "Traces", el: () => <Traces />, group: 1 },
  { path: "/connect", label: "Connect an agent", el: (me) => <Connect me={me} />, group: 1 },
];


const Logo = () => (
  <svg viewBox="0 0 32 32" aria-hidden="true">
    <rect width="32" height="32" rx="7" fill="var(--harbor)" />
    <path d="M8 24V11l8-4 8 4v13" fill="none" stroke="var(--harbor-ink)" strokeWidth="2.4" strokeLinejoin="round" />
    <path d="M12.5 24v-7h7v7" fill="none" stroke="var(--harbor-ink)" strokeWidth="2.4" />
  </svg>
);

function App() {
  const [me, setMe] = useState<Me | null>();
  const [path, setPath] = useState(location.pathname);
  useEffect(() => {
    const on = () => setPath(location.pathname);
    window.addEventListener("popstate", on);
    return () => window.removeEventListener("popstate", on);
  }, []);
  useEffect(() => {
    api<Me>("/me").then(setMe, () => setMe(null));
  }, []);
  useEffect(() => {
    const r = ROUTES.find((x) => x.path === path);
    document.title = r && r.path !== "/" ? `${r.label} - AgentGate` : "AgentGate";
  }, [path]);

  if (me === undefined) return null;
  if (me === null) return <Login onIn={(m) => setMe(m)} />;
  const route = ROUTES.find((r) => r.path === path) ?? ROUTES[0]!;

  return (
    <div className="shell">
      <nav className="rail" aria-label="Main">
        <div className="brand">
          <Logo /> AgentGate
        </div>
        {ROUTES.map((r, i) => (
          <span key={r.path} style={{ display: "contents" }}>
            {i > 0 && r.group !== ROUTES[i - 1]!.group && <div className="sep" />}
            <a
              href={r.path}
              aria-current={route.path === r.path ? "page" : undefined}
              onClick={(e) => {
                e.preventDefault();
                navigate(r.path);
              }}
            >
              {r.label}
            </a>
          </span>
        ))}
        <div className="who">
          {me.name}
          <br />
          {me.admin ? "Admin" : me.groups.join(", ")}
          <br />
          <button
            className="small"
            onClick={async () => {
              await api("/logout", { method: "POST" });
              setMe(null);
            }}
          >
            Sign out
          </button>
        </div>
      </nav>
      {route.el(me)}
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
