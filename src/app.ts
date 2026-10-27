import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Hono } from "hono";
import { serveStatic } from "@hono/node-server/serve-static";
import { config } from "./config.js";
import { db } from "./db/index.js";
import { adminRoutes } from "./admin.js";
import { oauthRoutes } from "./auth/oauth.js";
import { handleMcp } from "./gateway/mcp.js";
import { simRoutes } from "./sim/index.js";
import { registry } from "./telemetry.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WEB = path.join(ROOT, "web", "dist");

export function buildApp() {
  const app = new Hono();

  app.use("*", async (c, next) => {
    await next();
    c.header("X-Content-Type-Options", "nosniff");
    c.header("Referrer-Policy", "no-referrer");
    c.header("X-Frame-Options", "DENY");
    if (config.publicUrl.startsWith("https")) c.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    if ((c.res.headers.get("content-type") ?? "").includes("text/html"))
      c.header(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self' *; base-uri 'none'",
      );
  });

  // Cloud Run's front end reserves paths ending in "z" (it answers /healthz itself with 404), so the probe is /health.
  app.get("/health", async (c) => {
    try {
      await db().query("SELECT 1");
      return c.json({ ok: true });
    } catch {
      return c.json({ ok: false }, 503);
    }
  });

  app.get("/metrics", async (c) => {
    const want = process.env.METRICS_TOKEN;
    if (want && c.req.header("authorization") !== `Bearer ${want}`) return c.text("unauthorized", 401);
    c.header("content-type", registry.contentType);
    return c.body(await registry.metrics());
  });

  app.route("/", oauthRoutes());
  app.all("/mcp", (c) => handleMcp(c));
  app.route("/api", adminRoutes());

  // Simulated GitHub/Slack/Jira. Reachable only from this process in production mode.
  app.use("/sim/*", async (c, next) => {
    const ip = (c.env as { incoming?: { socket?: { remoteAddress?: string } } })?.incoming?.socket?.remoteAddress ?? "";
    if (!config.demo || !/^(::1|127\.0\.0\.1|::ffff:127\.0\.0\.1)$/.test(ip)) return c.json({ message: "Not Found" }, 404);
    return next();
  });
  app.route("/sim", simRoutes());

  app.get("/docs", (c) => c.redirect("https://github.com/Nags-gk/agentgate#readme"));

  if (existsSync(WEB)) {
    app.use("/assets/*", serveStatic({ root: path.relative(process.cwd(), WEB) }));
    app.get("/favicon.svg", serveStatic({ path: path.relative(process.cwd(), path.join(WEB, "favicon.svg")) }));
    // Read per request: tiny file, and a rebuilt UI is picked up without a restart.
    app.get("*", (c) => c.html(readFileSync(path.join(WEB, "index.html"), "utf8")));
  }
  return app;
}
