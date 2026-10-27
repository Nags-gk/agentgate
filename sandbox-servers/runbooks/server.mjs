// A small third-party-style MCP server run inside the AgentGate sandbox. It searches the
// markdown runbooks shipped in its own directory, the only files the sandbox lets it read.
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), "docs");
const docs = readdirSync(dir)
  .filter((f) => f.endsWith(".md"))
  .map((f) => ({ id: f.replace(/\.md$/, ""), text: readFileSync(path.join(dir, f), "utf8") }));

const server = new McpServer({ name: "runbooks", version: "0.1.0" });

server.registerTool(
  "search",
  { title: "Search runbooks", description: "Find runbooks matching words in the query.", inputSchema: { query: z.string().min(1) } },
  async ({ query }) => {
    const words = query.toLowerCase().split(/\W+/).filter(Boolean);
    const hits = docs
      .map((d) => ({ id: d.id, title: d.text.split("\n")[0].replace(/^#\s*/, ""), score: words.filter((w) => d.text.toLowerCase().includes(w)).length }))
      .filter((d) => d.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, 5);
    return { content: [{ type: "text", text: JSON.stringify(hits) }] };
  },
);

server.registerTool(
  "read",
  { title: "Read runbook", description: "Read a runbook by id.", inputSchema: { id: z.string().regex(/^[a-z0-9-]+$/) } },
  async ({ id }) => {
    const d = docs.find((x) => x.id === id);
    if (!d) return { isError: true, content: [{ type: "text", text: `no runbook ${id}` }] };
    return { content: [{ type: "text", text: d.text }] };
  },
);

await server.connect(new StdioServerTransport());
