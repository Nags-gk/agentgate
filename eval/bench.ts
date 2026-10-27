/**
 * Gateway overhead benchmark: sequential and concurrent tool calls through real MCP over
 * HTTP against a running AgentGate (simulated upstreams), compared with calling the same
 * upstream directly. Overhead = gateway latency minus direct latency.
 *
 *   PORT=8787 npx tsx eval/bench.ts [--calls 300] [--concurrency 8]
 */
import { mkdir, writeFile } from "node:fs/promises";
import { config, resourceUrl } from "../src/config.js";
import { closeDb, q1 } from "../src/db/index.js";
import { issueAccessToken } from "../src/auth/tokens.js";
import { DirectProvider, GatewayProvider } from "../src/agents/providers.js";

const arg = (k: string, d: number) => {
  const i = process.argv.indexOf(`--${k}`);
  return i > 0 ? Number(process.argv[i + 1]) : d;
};
const N = arg("calls", 300);
const C = arg("concurrency", 8);

const pct = (xs: number[], p: number) => {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))]!;
};

async function timed(n: number, conc: number, fn: (worker: number) => Promise<unknown>) {
  const lat: number[] = [];
  let next = 0;
  const t0 = performance.now();
  await Promise.all(
    Array.from({ length: conc }, async (_, w) => {
      while (next++ < n) {
        const s = performance.now();
        await fn(w);
        lat.push(performance.now() - s);
      }
    }),
  );
  const secs = (performance.now() - t0) / 1000;
  return { p50: pct(lat, 50), p95: pct(lat, 95), p99: pct(lat, 99), rps: lat.length / secs };
}

const owner = await q1<{ tenant_id: string; id: string }>("SELECT tenant_id, id FROM users WHERE email = 'dana@acme.test'");
if (!owner) throw new Error("seed the demo tenant first");
const agent = await q1<{ id: string }>("INSERT INTO agents (tenant_id, name, owner_user_id, bundle_id, disabled) VALUES ($1,'eval-bench',$2,'read-only',false) RETURNING id", [owner.tenant_id, owner.id]);
const token = await issueAccessToken({ sub: owner.id, aud: resourceUrl(), tid: owner.tenant_id, bid: "read-only", cid: "bench", fam: agent!.id, agt: agent!.id });

// One MCP session per concurrent worker, as with separate agents (calls within a session are ordered).
const gws = await Promise.all(Array.from({ length: C }, () => GatewayProvider.connect(`http://127.0.0.1:${config.port}/mcp`, token)));
const gw = gws[0]!;
const direct = new DirectProvider(`http://127.0.0.1:${config.port}/sim`);
const call = { tool: "github_get_issue", args: { repo: "acme/website", number: 8 } };

// Warm up both paths.
for (let i = 0; i < 20; i++) {
  await gw.call(call.tool, call.args);
  await direct.call(call.tool, call.args);
}

const results = {
  calls: N,
  concurrency: C,
  direct_sequential: await timed(N, 1, () => direct.call(call.tool, call.args)),
  gateway_sequential: await timed(N, 1, () => gw.call(call.tool, call.args)),
  direct_concurrent: await timed(N, C, () => direct.call(call.tool, call.args)),
  gateway_concurrent: await timed(N, C, (w) => gws[w]!.call(call.tool, call.args)),
};
const overhead = {
  p50_ms: results.gateway_sequential.p50 - results.direct_sequential.p50,
  p95_ms: results.gateway_sequential.p95 - results.direct_sequential.p95,
};
console.log(JSON.stringify({ ...results, overhead }, (_k, v) => (typeof v === "number" ? Math.round(v * 10) / 10 : v), 1));
await mkdir(new URL("./results/", import.meta.url), { recursive: true });
await writeFile(new URL("./results/bench.json", import.meta.url), JSON.stringify({ ...results, overhead, note: "single CockroachDB node and gateway on one host; simulated upstream" }, null, 1));
await Promise.all(gws.map((g) => g.close()));
await closeDb();
