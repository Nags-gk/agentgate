import { http, str, type Connector, type ToolDef } from "./types.js";

const key = { type: "string", description: "Issue key, e.g. WEB-12", pattern: "^[A-Z][A-Z0-9]+-\\d+$" };
const project = { type: "string", description: "Project key, e.g. WEB", pattern: "^[A-Z][A-Z0-9]+$" };

const tools: ToolDef[] = [
  {
    name: "jira_search",
    title: "Search issues",
    description: "Search issues in a project, optionally filtered by text.",
    inputSchema: { type: "object", properties: { project, text: { type: "string" } }, required: ["project"] },
    action: "read",
    risk: "low",
  },
  {
    name: "jira_get_issue",
    title: "Get issue",
    description: "Read one issue with its description.",
    inputSchema: { type: "object", properties: { key }, required: ["key"] },
    action: "read",
    risk: "low",
  },
  {
    name: "jira_create_issue",
    title: "Create issue",
    description: "Create an issue in a project.",
    inputSchema: {
      type: "object",
      properties: { project, summary: { type: "string", maxLength: 255 }, description: { type: "string", maxLength: 20000 } },
      required: ["project", "summary"],
    },
    action: "write",
    risk: "medium",
  },
  {
    name: "jira_add_comment",
    title: "Comment on issue",
    description: "Add a comment to an issue.",
    inputSchema: { type: "object", properties: { key, body: { type: "string", maxLength: 20000 } }, required: ["key", "body"] },
    action: "write",
    risk: "medium",
  },
];

/** Jira Cloud uses Atlassian Document Format; flatten it to plain text for agents. */
export function adfToText(node: unknown): string {
  if (node == null) return "";
  if (typeof node === "string") return node;
  const n = node as { type?: string; text?: string; content?: unknown[] };
  if (n.type === "text") return n.text ?? "";
  const inner = (n.content ?? []).map(adfToText).join(n.type === "doc" ? "\n" : "");
  return n.type === "paragraph" ? inner + "\n" : inner;
}
const textToAdf = (text: string) => ({
  type: "doc",
  version: 1,
  content: text.split("\n").map((line) => ({ type: "paragraph", content: line ? [{ type: "text", text: line }] : [] })),
});

const projectOf = (args: Record<string, unknown>): string | undefined => {
  if (typeof args.project === "string") return args.project;
  if (typeof args.key === "string") return args.key.split("-")[0];
  return undefined;
};

export const jira: Connector = {
  id: "jira",
  name: "Jira",
  description: "Projects, issues and comments.",
  tools,
  directTokenScopes: ["read:jira-work", "write:jira-work", "manage:jira-project", "read:jira-user"],
  resource: (_tool, args) => {
    const p = projectOf(args);
    return p ? `jira:${p}` : undefined;
  },
  async call(tool, args, ctx) {
    switch (tool) {
      case "jira_search": {
        const jql = `project = ${str(args, "project")}` + (typeof args.text === "string" && args.text ? ` AND text ~ "${args.text.replace(/["\\]/g, "")}"` : "");
        const r = (await http(ctx, "GET", `/rest/api/3/search/jql?jql=${encodeURIComponent(jql)}&fields=summary,status`)) as {
          issues: Array<{ key: string; fields: { summary: string; status?: { name: string } } }>;
        };
        return { data: r.issues.map((i) => ({ key: i.key, summary: i.fields.summary, status: i.fields.status?.name })) };
      }
      case "jira_get_issue": {
        const i = (await http(ctx, "GET", `/rest/api/3/issue/${encodeURIComponent(str(args, "key"))}`)) as {
          key: string;
          fields: { summary: string; description?: unknown; status?: { name: string } };
        };
        return { data: { key: i.key, summary: i.fields.summary, status: i.fields.status?.name, description: adfToText(i.fields.description).trim() } };
      }
      case "jira_create_issue": {
        const r = (await http(ctx, "POST", "/rest/api/3/issue", {
          body: {
            fields: {
              project: { key: str(args, "project") },
              summary: str(args, "summary"),
              issuetype: { name: "Task" },
              description: textToAdf(typeof args.description === "string" ? args.description : ""),
            },
          },
        })) as { key: string };
        return { data: { key: r.key } };
      }
      case "jira_add_comment": {
        const r = (await http(ctx, "POST", `/rest/api/3/issue/${encodeURIComponent(str(args, "key"))}/comment`, {
          body: { body: textToAdf(str(args, "body")) },
        })) as { id: string };
        return { data: { id: r.id } };
      }
    }
    throw new Error(`unknown tool ${tool}`);
  },
};
