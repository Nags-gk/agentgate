import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { buildApp } from "./app.js";
import { config } from "./config.js";
import { closeDb } from "./db/index.js";
import { migrate } from "./db/migrate.js";
import { reloadSigningKeys, rotateSigningKey, signingKey } from "./auth/crypto.js";
import { startConnectors, stopConnectors } from "./gateway/registry.js";
import { seedDemo } from "./seed.js";
import { resetSims } from "./sim/index.js";
import { bootstrapDemoTraffic } from "./demo.js";

/**
 * Listen first, initialize second. Cloud Run kills a container that does not open its port
 * in time, and against a remote CockroachDB cluster the first boot (migrations, seeding)
 * can take a while. Until init finishes, every request gets 503 with the current step.
 */
let ready: ReturnType<typeof buildApp> | undefined;
let step = "starting";
let failure: string | undefined;

const gate = new Hono();
gate.all("*", (c) => {
  if (ready) return ready.fetch(c.req.raw, c.env);
  return c.json({ ok: false, starting: step, error: failure }, 503);
});

const server = serve({ fetch: gate.fetch, port: config.port, hostname: "0.0.0.0" }, (info) => {
  console.log(`AgentGate listening on :${info.port} (${config.publicUrl}, demo=${config.demo}); initializing`);
});

async function init() {
  const t0 = Date.now();
  const at = (s: string) => {
    step = s;
    console.log(`init: ${s} (+${Date.now() - t0} ms)`);
  };
  at("connecting to the database and running migrations");
  await migrate();
  at("loading signing keys");
  await signingKey();
  await rotateSigningKey({ maxAgeDays: 30 });
  setInterval(() => {
    rotateSigningKey({ maxAgeDays: 30 })
      .then(() => reloadSigningKeys())
      .catch((e) => console.error("key rotation failed", e));
  }, 3600_000).unref();
  if (config.demo) {
    at("seeding the demo tenant");
    await seedDemo();
    setInterval(() => {
      resetSims();
      seedDemo().catch((e) => console.error("demo reseed failed", e));
    }, 3600_000).unref();
  }
  at("starting sandboxed MCP servers");
  await startConnectors();
  ready = buildApp();
  at("ready");
  if (config.demo) bootstrapDemoTraffic().catch((e) => console.error("demo traffic failed", e));
}

// Retry init with backoff instead of crashing: a database hiccup at boot should not take the
// service into a restart loop, and the error stays visible at /health.
(async () => {
  for (let attempt = 1; !ready; attempt++) {
    try {
      await init();
    } catch (e) {
      failure = `${(e as Error).message}`;
      console.error(`init failed (attempt ${attempt}) during "${step}":`, e);
      await new Promise((r) => setTimeout(r, Math.min(30_000, 2_000 * attempt)));
    }
  }
  failure = undefined;
})();

async function shutdown() {
  console.log("shutting down");
  server.close();
  await stopConnectors();
  await closeDb();
  process.exit(0);
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
