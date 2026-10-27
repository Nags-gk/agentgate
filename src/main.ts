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

await migrate();
await signingKey();
await rotateSigningKey({ maxAgeDays: 30 });
setInterval(() => {
  rotateSigningKey({ maxAgeDays: 30 })
    .then(() => reloadSigningKeys())
    .catch((e) => console.error("key rotation failed", e));
}, 3600_000).unref();
if (config.demo) {
  await seedDemo();
  // The public demo restores its policy and simulated workspace every hour.
  setInterval(() => {
    resetSims();
    seedDemo().catch((e) => console.error("demo reseed failed", e));
  }, 3600_000).unref();
}
await startConnectors();

const server = serve({ fetch: buildApp().fetch, port: config.port, hostname: "0.0.0.0" }, (info) => {
  console.log(`AgentGate listening on :${info.port} (${config.publicUrl}, demo=${config.demo})`);
  if (config.demo) bootstrapDemoTraffic().catch((e) => console.error("demo traffic failed", e));
});

async function shutdown() {
  console.log("shutting down");
  server.close();
  await stopConnectors();
  await closeDb();
  process.exit(0);
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
