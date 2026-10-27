import { http, str, UpstreamError, type CallContext, type Connector, type ToolDef } from "./types.js";

const channel = { type: "string", description: "Channel name with #, e.g. #eng", pattern: "^#[a-z0-9_-]+$" };

const tools: ToolDef[] = [
  {
    name: "slack_list_channels",
    title: "List channels",
    description: "List channels, including whether each is shared with external organizations.",
    inputSchema: { type: "object", properties: {} },
    action: "read",
    risk: "low",
  },
  {
    name: "slack_read_channel",
    title: "Read channel",
    description: "Read recent messages from a channel.",
    inputSchema: { type: "object", properties: { channel, limit: { type: "integer", minimum: 1, maximum: 100 } }, required: ["channel"] },
    action: "read",
    risk: "low",
  },
  {
    name: "slack_post_message",
    title: "Post message",
    description: "Post a message to a channel.",
    inputSchema: { type: "object", properties: { channel, text: { type: "string", maxLength: 4000 } }, required: ["channel", "text"] },
    action: "write",
    risk: "medium",
  },
];

/** Slack's Web API returns HTTP 200 with {ok:false} on errors. */
async function slack(ctx: CallContext, method: string, params: Record<string, unknown>): Promise<Record<string, unknown>> {
  const r = (await http(ctx, "POST", `/api/${method}`, { body: params })) as Record<string, unknown>;
  if (!r.ok) throw new UpstreamError(`slack ${method}: ${String(r.error ?? "error")}`, 400);
  return r;
}

export const slackConnector: Connector = {
  id: "slack",
  name: "Slack",
  description: "Channels and messages.",
  tools,
  directTokenScopes: ["channels:history", "channels:read", "chat:write", "groups:history", "im:history", "users:read"],
  resource: (_tool, args) => (typeof args.channel === "string" ? `slack:${args.channel}` : undefined),
  async call(tool, args, ctx) {
    switch (tool) {
      case "slack_list_channels": {
        const r = await slack(ctx, "conversations.list", {});
        return { data: r.channels };
      }
      case "slack_read_channel": {
        const r = await slack(ctx, "conversations.history", {
          channel: str(args, "channel"),
          limit: typeof args.limit === "number" ? args.limit : 20,
        });
        return { data: r.messages };
      }
      case "slack_post_message": {
        const r = await slack(ctx, "chat.postMessage", { channel: str(args, "channel"), text: str(args, "text") });
        return { data: { ts: r.ts, channel: r.channel } };
      }
    }
    throw new Error(`unknown tool ${tool}`);
  },
};
