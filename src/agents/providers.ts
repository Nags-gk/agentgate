import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { allTools, connectorFor } from "../gateway/registry.js";
import { SIM_TOKENS } from "../sim/index.js";
import type { JsonSchema } from "../connectors/types.js";

export interface ToolInfo {
  name: string;
  description: string;
  inputSchema: JsonSchema;
}
export interface ToolResult {
  text: string;
  isError: boolean;
}

/** What an agent sees: a tool list and a way to call tools. */
export interface ToolProvider {
  label: string;
  list(): Promise<ToolInfo[]>;
  call(name: string, args: Record<string, unknown>): Promise<ToolResult>;
  close(): Promise<void>;
}

/** Tools through AgentGate, over real MCP (Streamable HTTP) with an OAuth bearer token. */
export class GatewayProvider implements ToolProvider {
  label = "agentgate";
  private constructor(private readonly client: Client) {}

  static async connect(mcpUrl: string, accessToken: string): Promise<GatewayProvider> {
    const client = new Client({ name: "agentgate-eval", version: "0.1.0" });
    const transport = new StreamableHTTPClientTransport(new URL(mcpUrl), {
      requestInit: { headers: { authorization: `Bearer ${accessToken}` } },
    });
    await client.connect(transport);
    return new GatewayProvider(client);
  }

  async list(): Promise<ToolInfo[]> {
    const r = await this.client.listTools();
    return r.tools.map((t) => ({ name: t.name, description: t.description ?? "", inputSchema: t.inputSchema as JsonSchema }));
  }

  async call(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    const r = await this.client.callTool({ name, arguments: args });
    const text = (r.content as Array<{ type: string; text?: string }>).map((c) => c.text ?? "").join("\n");
    return { text, isError: !!r.isError };
  }

  close() {
    return this.client.close();
  }
}

/**
 * The baseline AgentGate replaces: the agent holds the user's raw upstream tokens and calls
 * the APIs directly. Every tool, every resource, no data-flow rules, no redaction, no audit.
 */
export class DirectProvider implements ToolProvider {
  label = "direct-token";
  constructor(private readonly simBase: string) {}

  async list(): Promise<ToolInfo[]> {
    return allTools()
      .filter((t) => !t.name.startsWith("runbooks_"))
      .map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema }));
  }

  async call(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    const c = connectorFor(name);
    if (!c) return { text: `unknown tool ${name}`, isError: true };
    try {
      const r = await c.call(name, args, {
        credential: SIM_TOKENS[c.id as keyof typeof SIM_TOKENS],
        signal: AbortSignal.timeout(15_000),
        baseUrl: `${this.simBase}/${c.id}`,
      });
      return { text: JSON.stringify(r.data, null, 1), isError: false };
    } catch (e) {
      return { text: `error: ${(e as Error).message}`, isError: true };
    }
  }

  async close() {}
}
