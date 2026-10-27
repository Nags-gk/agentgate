import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { metrics } from "../telemetry.js";
import { UpstreamError, type Connector, type ToolDef } from "./types.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

export interface SandboxSpec {
  id: string;
  name: string;
  description: string;
  /** Entry file, relative to sandbox-servers/<id>/. */
  entry: string;
  /** Hosts the server may connect to. Empty = no network at all. */
  egress: string[];
  /** Environment variables the server receives (credentials are injected per call, not here). */
  env?: Record<string, string>;
  /** Tools that change state; everything else is treated as a read. */
  writeTools?: string[];
  memoryMb?: number;
  outputCapBytes?: number;
}

/**
 * Builds the command line that runs an untrusted stdio MCP server under Node's permission
 * model: it may read only its own directory and the MCP SDK, write nothing, spawn nothing,
 * start no workers, load no native addons, and connect only to allowlisted hosts.
 */
export function sandboxCommand(spec: SandboxSpec): { command: string; args: string[]; env: Record<string, string>; cwd: string } {
  const dir = path.join(ROOT, "sandbox-servers", spec.id);
  const reads = [dir, path.join(ROOT, "node_modules"), path.join(ROOT, "sandbox", "egress-guard.mjs")];
  return {
    command: process.execPath,
    args: [
      "--permission",
      ...reads.map((r) => `--allow-fs-read=${r}`),
      `--max-old-space-size=${spec.memoryMb ?? 96}`,
      "--disallow-code-generation-from-strings",
      "--import",
      path.join(ROOT, "sandbox", "egress-guard.mjs"),
      path.join(dir, spec.entry),
    ],
    // Only what is listed here reaches the child: no database URL, no vault keys, no API keys.
    env: { NODE_ENV: "production", AGENTGATE_EGRESS_ALLOW: spec.egress.join(","), ...(spec.env ?? {}) },
    cwd: dir,
  };
}

/** A connector backed by a sandboxed stdio MCP server, restarted on crash. */
export class SandboxedConnector implements Connector {
  tools: ToolDef[] = [];
  directTokenScopes = ["(process-level access to the host)"];
  private client?: Client;
  private starting?: Promise<Client>;
  private restarts = 0;

  constructor(readonly spec: SandboxSpec) {}
  get id() {
    return this.spec.id;
  }
  get name() {
    return this.spec.name;
  }
  get description() {
    return this.spec.description;
  }

  resource(): string | undefined {
    return `${this.spec.id}:*`;
  }

  async start(): Promise<Client> {
    if (this.client) return this.client;
    this.starting ??= (async () => {
      const cmd = sandboxCommand(this.spec);
      const transport = new StdioClientTransport({ command: cmd.command, args: cmd.args, env: cmd.env, cwd: cmd.cwd, stderr: "pipe" });
      const client = new Client({ name: "agentgate", version: "0.1.0" });
      transport.onclose = () => {
        this.client = undefined;
        this.starting = undefined;
      };
      await client.connect(transport);
      const listed = await client.listTools();
      this.tools = listed.tools.map((t) => ({
        name: `${this.spec.id}_${t.name}`,
        title: t.title ?? t.name,
        description: t.description ?? "",
        inputSchema: (t.inputSchema as ToolDef["inputSchema"]) ?? { type: "object", properties: {} },
        action: this.spec.writeTools?.includes(t.name) ? "write" : "read",
        risk: this.spec.writeTools?.includes(t.name) ? "medium" : "low",
      }));
      this.client = client;
      return client;
    })();
    try {
      return await this.starting;
    } catch (e) {
      this.starting = undefined;
      throw e;
    }
  }

  async stop(): Promise<void> {
    await this.client?.close().catch(() => {});
    this.client = undefined;
    this.starting = undefined;
  }

  async call(tool: string, args: Record<string, unknown>, ctx: { signal: AbortSignal }) {
    const client = await this.start();
    const inner = tool.slice(this.spec.id.length + 1);
    try {
      const res = await client.callTool({ name: inner, arguments: args }, undefined, { signal: ctx.signal, timeout: 10_000 });
      const text = (res.content as Array<{ type: string; text?: string }>)
        .filter((c) => c.type === "text")
        .map((c) => c.text)
        .join("\n");
      const cap = this.spec.outputCapBytes ?? 256 * 1024;
      if (Buffer.byteLength(text) > cap) {
        metrics.sandboxKills.inc({ reason: "output_cap" });
        throw new UpstreamError(`sandboxed server output exceeded ${cap} bytes`, 502);
      }
      if (res.isError) throw new UpstreamError(text || "tool error", 400);
      let data: unknown = text;
      try {
        data = JSON.parse(text);
      } catch {
        /* plain text */
      }
      return { data };
    } catch (err) {
      if (err instanceof UpstreamError) throw err;
      // Timeouts and crashes: kill the process so the next call starts clean.
      metrics.sandboxKills.inc({ reason: /timed out/i.test(String(err)) ? "timeout" : "crash" });
      this.restarts++;
      await this.stop();
      throw new UpstreamError(`sandboxed server failed: ${(err as Error).message}`, 502);
    }
  }
}
