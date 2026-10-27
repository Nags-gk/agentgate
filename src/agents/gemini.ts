import { GoogleGenAI, type Content, type FunctionDeclaration } from "@google/genai";
import type { CallLog } from "./scenarios.js";
import type { ToolProvider } from "./providers.js";

const SYSTEM = `You are Acme's operations assistant. You have tools for GitHub, Slack, Jira and team runbooks.
Complete the user's task using the tools. Be efficient: call tools, then finish with a short summary of what you did.`;

const PREFERRED = [/^gemini-[\d.]+-flash$/, /^gemini-[\d.]+-flash/, /flash/];
const SKIP = ["lite", "image", "tts", "live", "audio", "embedding", "thinking", "exp", "preview", "vision"];

export async function pickGeminiModel(ai: GoogleGenAI): Promise<string> {
  const ids: string[] = [];
  const pager = await ai.models.list();
  for await (const m of pager) {
    const name = (m.name ?? "").replace("models/", "");
    if ((m.supportedActions ?? []).includes("generateContent") && !SKIP.some((s) => name.includes(s))) ids.push(name);
  }
  ids.sort((a, b) => b.localeCompare(a, undefined, { numeric: true }));
  for (const re of PREFERRED) {
    const hit = ids.find((i) => re.test(i));
    if (hit) return hit;
  }
  throw new Error("no Gemini Flash model available for this key");
}

async function withRetry<T>(fn: () => Promise<T>): Promise<T> {
  let delay = 4000;
  for (let i = 0; ; i++) {
    try {
      return await fn();
    } catch (e) {
      const msg = String((e as Error).message);
      if (i >= 6 || !/429|503|500|UNAVAILABLE|RESOURCE_EXHAUSTED|overloaded/i.test(msg)) throw e;
      const m = /retry in ([\d.]+)s/i.exec(msg);
      await new Promise((r) => setTimeout(r, m ? Number(m[1]) * 1000 + 500 : delay));
      delay = Math.min(delay * 2, 60_000);
    }
  }
}

export interface AgentRun {
  calls: CallLog[];
  finalText: string;
  turns: number;
  model: string;
}

/** A plain function-calling loop: the model sees the provider's tools and acts on the task. */
export async function runGeminiAgent(provider: ToolProvider, task: string, opts: { apiKey: string; model?: string; maxTurns?: number }): Promise<AgentRun> {
  const ai = new GoogleGenAI({ apiKey: opts.apiKey });
  const model = opts.model ?? (await pickGeminiModel(ai));
  const tools = await provider.list();
  const decls: FunctionDeclaration[] = tools.map((t) => ({ name: t.name, description: t.description, parametersJsonSchema: t.inputSchema }));
  const contents: Content[] = [{ role: "user", parts: [{ text: task }] }];
  const calls: CallLog[] = [];
  let finalText = "";
  let turns = 0;
  for (; turns < (opts.maxTurns ?? 12); turns++) {
    const r = await withRetry(() =>
      ai.models.generateContent({
        model,
        contents,
        config: { systemInstruction: SYSTEM, tools: decls.length ? [{ functionDeclarations: decls }] : undefined, temperature: 0 },
      }),
    );
    const content = r.candidates?.[0]?.content;
    if (!content) break;
    contents.push(content);
    const fcs = (content.parts ?? []).filter((p) => p.functionCall).map((p) => p.functionCall!);
    if (!fcs.length) {
      finalText = (content.parts ?? []).map((p) => p.text ?? "").join("");
      break;
    }
    const responses = [];
    for (const fc of fcs) {
      const args = (fc.args ?? {}) as Record<string, unknown>;
      const res = await provider.call(fc.name ?? "", args);
      calls.push({ tool: fc.name ?? "", args, isError: res.isError, text: res.text.slice(0, 4000) });
      responses.push({ functionResponse: { id: fc.id, name: fc.name, response: res.isError ? { error: res.text } : { result: res.text } } });
    }
    contents.push({ role: "user", parts: responses });
  }
  return { calls, finalText, turns, model };
}
