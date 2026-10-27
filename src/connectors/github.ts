import { http, str, type Connector, type ToolDef } from "./types.js";

const repo = { type: "string", description: "owner/name, e.g. acme/website", pattern: "^[\\w.-]+/[\\w.-]+$" };
const enc = (r: string) => r.split("/").map(encodeURIComponent).join("/");

const tools: ToolDef[] = [
  {
    name: "github_list_repos",
    title: "List repositories",
    description: "List repositories the connected account can see.",
    inputSchema: { type: "object", properties: {} },
    action: "read",
    risk: "low",
  },
  {
    name: "github_list_issues",
    title: "List issues",
    description: "List open issues in a repository.",
    inputSchema: { type: "object", properties: { repo, state: { type: "string", enum: ["open", "closed", "all"] } }, required: ["repo"] },
    action: "read",
    risk: "low",
  },
  {
    name: "github_get_issue",
    title: "Get issue",
    description: "Read one issue with its body.",
    inputSchema: { type: "object", properties: { repo, number: { type: "integer", minimum: 1 } }, required: ["repo", "number"] },
    action: "read",
    risk: "low",
  },
  {
    name: "github_get_file",
    title: "Read file",
    description: "Read a file from a repository's default branch.",
    inputSchema: { type: "object", properties: { repo, path: { type: "string" } }, required: ["repo", "path"] },
    action: "read",
    risk: "low",
  },
  {
    name: "github_comment_issue",
    title: "Comment on issue",
    description: "Add a comment to an issue.",
    inputSchema: {
      type: "object",
      properties: { repo, number: { type: "integer", minimum: 1 }, body: { type: "string", maxLength: 20000 } },
      required: ["repo", "number", "body"],
    },
    action: "write",
    risk: "medium",
  },
  {
    name: "github_create_issue",
    title: "Create issue",
    description: "Open a new issue.",
    inputSchema: {
      type: "object",
      properties: { repo, title: { type: "string", maxLength: 256 }, body: { type: "string", maxLength: 20000 } },
      required: ["repo", "title"],
    },
    action: "write",
    risk: "medium",
  },
  {
    name: "github_delete_repo",
    title: "Delete repository",
    description: "Permanently delete a repository.",
    inputSchema: { type: "object", properties: { repo }, required: ["repo"] },
    action: "write",
    risk: "high",
  },
];

export const github: Connector = {
  id: "github",
  name: "GitHub",
  description: "Repositories, issues and files.",
  tools,
  directTokenScopes: ["repo", "read:org", "workflow", "delete_repo"],
  resource: (_tool, args) => (typeof args.repo === "string" ? `github:${args.repo}` : undefined),
  async call(tool, args, ctx) {
    switch (tool) {
      case "github_list_repos": {
        const r = (await http(ctx, "GET", "/user/repos?per_page=100")) as Array<Record<string, unknown>>;
        return { data: r.map((x) => ({ full_name: x.full_name, private: x.private, description: x.description })) };
      }
      case "github_list_issues": {
        const state = typeof args.state === "string" ? args.state : "open";
        const r = (await http(ctx, "GET", `/repos/${enc(str(args, "repo"))}/issues?state=${state}&per_page=50`)) as Array<
          Record<string, unknown>
        >;
        return { data: r.map((i) => ({ number: i.number, title: i.title, state: i.state, user: (i.user as { login?: string })?.login })) };
      }
      case "github_get_issue": {
        const i = (await http(ctx, "GET", `/repos/${enc(str(args, "repo"))}/issues/${Number(args.number)}`)) as Record<string, unknown>;
        return { data: { number: i.number, title: i.title, state: i.state, body: i.body, user: (i.user as { login?: string })?.login } };
      }
      case "github_get_file": {
        const path = str(args, "path").replace(/^\/+/, "");
        const f = (await http(ctx, "GET", `/repos/${enc(str(args, "repo"))}/contents/${path.split("/").map(encodeURIComponent).join("/")}`)) as {
          content?: string;
          encoding?: string;
          path?: string;
        };
        const text = f.encoding === "base64" ? Buffer.from(f.content ?? "", "base64").toString("utf8") : (f.content ?? "");
        return { data: { path: f.path, content: text } };
      }
      case "github_comment_issue": {
        const c = (await http(ctx, "POST", `/repos/${enc(str(args, "repo"))}/issues/${Number(args.number)}/comments`, {
          body: { body: str(args, "body") },
        })) as Record<string, unknown>;
        return { data: { id: c.id, url: c.html_url } };
      }
      case "github_create_issue": {
        const c = (await http(ctx, "POST", `/repos/${enc(str(args, "repo"))}/issues`, {
          body: { title: str(args, "title"), body: typeof args.body === "string" ? args.body : "" },
        })) as Record<string, unknown>;
        return { data: { number: c.number, url: c.html_url } };
      }
      case "github_delete_repo": {
        await http(ctx, "DELETE", `/repos/${enc(str(args, "repo"))}`);
        return { data: { deleted: args.repo } };
      }
    }
    throw new Error(`unknown tool ${tool}`);
  },
};
