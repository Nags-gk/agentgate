import { afterAll, beforeAll, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { UnauthorizedError, type OAuthClientProvider } from "@modelcontextprotocol/sdk/client/auth.js";
import { BASE, startApp, stopApp } from "./helpers.js";

beforeAll(startApp);
afterAll(stopApp);

/**
 * Conformance check: the official MCP SDK client discovers and completes AgentGate's OAuth
 * flow on its own (401 -> resource metadata -> server metadata -> dynamic registration ->
 * PKCE authorize -> token), the way Claude Code and other clients do. Only the browser step
 * (signing in and picking a bundle) is played by this test.
 */
it("works with the MCP SDK's own OAuth client", async () => {
  const redirect = "http://127.0.0.1:43111/callback";
  let codeFromBrowser: string | undefined;
  const store: { client?: unknown; tokens?: unknown; verifier?: string } = {};
  const provider: OAuthClientProvider = {
    get redirectUrl() {
      return redirect;
    },
    get clientMetadata() {
      return { client_name: "SDK conformance client", redirect_uris: [redirect], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none" };
    },
    clientInformation: () => store.client as never,
    saveClientInformation: (c) => void (store.client = c),
    tokens: () => store.tokens as never,
    saveTokens: (t) => void (store.tokens = t),
    saveCodeVerifier: (v) => void (store.verifier = v),
    codeVerifier: () => store.verifier!,
    async redirectToAuthorization(url: URL) {
      // The "browser": sign in, then allow with the read-only bundle.
      const params = Object.fromEntries(url.searchParams);
      const post = (body: Record<string, string>) =>
        fetch(`${BASE}/oauth/authorize`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(body), redirect: "manual" });
      const html = await (await post({ ...params, email: "dana@acme.test", password: "agentgate-demo" })).text();
      const ticket = /name="ticket" value="([^"]+)"/.exec(html)![1]!;
      const r = await post({ ...params, ticket, bundle: "read-only", decision: "allow" });
      codeFromBrowser = new URL(r.headers.get("location")!).searchParams.get("code")!;
    },
  };

  let transport = new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`), { authProvider: provider });
  const client = new Client({ name: "sdk-conformance", version: "1" });
  await expect(client.connect(transport)).rejects.toBeInstanceOf(UnauthorizedError);
  expect(codeFromBrowser).toBeTruthy();
  await transport.finishAuth(codeFromBrowser!);

  transport = new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`), { authProvider: provider });
  const client2 = new Client({ name: "sdk-conformance", version: "1" });
  await client2.connect(transport);
  const tools = (await client2.listTools()).tools;
  expect(tools.length).toBeGreaterThan(0);
  expect(tools.every((t) => t.annotations?.readOnlyHint)).toBe(true);
  await client2.close();
});
