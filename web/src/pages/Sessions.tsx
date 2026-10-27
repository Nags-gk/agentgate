import { api, ago } from "../api";
import { Err, Level, Page, useLoad } from "../ui";

interface S {
  id: string;
  client_id: string;
  bundle_id: string;
  agent_id: string | null;
  level: string;
  sources: string[];
  untrusted: string[];
  last_seen: string;
  calls: string;
  denied: string;
}

export function Sessions() {
  const s = useLoad(() => api<S[]>("/sessions"));
  return (
    <Page
      title="Sessions"
      lede="Each MCP session carries the most sensitive label of everything it has read. A session that has read confidential data cannot write to an internal or public place, and one that read a flagged prompt injection cannot write anywhere external."
    >
      <Err msg={s.error} />
      <div className="scroll">
        <table>
          <thead>
            <tr>
              <th>Session</th>
              <th>Bundle</th>
              <th>Highest data read</th>
              <th>Read from</th>
              <th>Flagged content from</th>
              <th className="num">Calls</th>
              <th className="num">Stopped</th>
              <th>Last active</th>
            </tr>
          </thead>
          <tbody>
            {(s.data ?? []).map((x) => (
              <tr key={x.id}>
                <td className="mono">{x.id.slice(0, 8)}</td>
                <td className="mono">{x.bundle_id}</td>
                <td>
                  <Level level={Number(x.level)} />
                </td>
                <td>
                  {x.sources.slice(0, 6).map((r) => (
                    <span className="chip code" key={r}>
                      {r}
                    </span>
                  ))}
                </td>
                <td>
                  {x.untrusted.length ? (
                    x.untrusted.map((r) => (
                      <span className="chip level-confidential" key={r}>
                        {r}
                      </span>
                    ))
                  ) : (
                    <span className="muted">none</span>
                  )}
                </td>
                <td className="num">{x.calls}</td>
                <td className="num">{x.denied}</td>
                <td>{ago(x.last_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!s.data?.length && <p className="muted">No sessions yet.</p>}
    </Page>
  );
}
