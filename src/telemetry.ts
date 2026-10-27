import client from "prom-client";
import { trace, SpanStatusCode, type Span } from "@opentelemetry/api";
import { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";
import {
  SimpleSpanProcessor,
  type ReadableSpan,
  type SpanExporter,
} from "@opentelemetry/sdk-trace-base";

// ---------------------------------------------------------------- metrics (Prometheus)
export const registry = new client.Registry();
client.collectDefaultMetrics({ register: registry });

export const metrics = {
  toolCalls: new client.Counter({
    name: "agentgate_tool_calls_total",
    help: "Tool calls through the gateway by decision",
    labelNames: ["connector", "tool", "decision"] as const,
    registers: [registry],
  }),
  toolLatency: new client.Histogram({
    name: "agentgate_tool_latency_seconds",
    help: "End-to-end tool call latency, including policy, guard and upstream",
    labelNames: ["connector"] as const,
    buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
    registers: [registry],
  }),
  policyLatency: new client.Histogram({
    name: "agentgate_policy_eval_seconds",
    help: "Time to evaluate policy and data-flow rules for one call",
    buckets: [0.0001, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025],
    registers: [registry],
  }),
  guardFindings: new client.Counter({
    name: "agentgate_guard_findings_total",
    help: "Secrets redacted and injections flagged",
    labelNames: ["kind"] as const,
    registers: [registry],
  }),
  authEvents: new client.Counter({
    name: "agentgate_auth_events_total",
    help: "OAuth and token events",
    labelNames: ["event"] as const,
    registers: [registry],
  }),
  rateLimited: new client.Counter({
    name: "agentgate_rate_limited_total",
    help: "Requests rejected by the per-principal rate limiter",
    registers: [registry],
  }),
  txRetries: new client.Counter({
    name: "agentgate_db_tx_retries_total",
    help: "CockroachDB SERIALIZABLE transaction retries (SQLSTATE 40001)",
    registers: [registry],
  }),
  sandboxKills: new client.Counter({
    name: "agentgate_sandbox_kills_total",
    help: "Sandboxed MCP server processes killed (timeout, output cap, crash)",
    labelNames: ["reason"] as const,
    registers: [registry],
  }),
};

// ---------------------------------------------------------------- traces (OpenTelemetry)
export interface SpanRecord {
  traceId: string;
  spanId: string;
  parentId?: string;
  name: string;
  startMs: number;
  durationMs: number;
  status: "ok" | "error";
  attributes: Record<string, unknown>;
}

/** Keeps the most recent spans in memory so the admin UI can show them without a backend. */
class RingExporter implements SpanExporter {
  readonly spans: SpanRecord[] = [];
  constructor(private readonly cap = 2000) {}
  export(spans: ReadableSpan[], done: (r: { code: number }) => void): void {
    for (const s of spans) {
      const [sec, ns] = s.startTime;
      const [dsec, dns] = s.duration;
      this.spans.push({
        traceId: s.spanContext().traceId,
        spanId: s.spanContext().spanId,
        parentId: s.parentSpanContext?.spanId,
        name: s.name,
        startMs: sec * 1e3 + ns / 1e6,
        durationMs: dsec * 1e3 + dns / 1e6,
        status: s.status.code === SpanStatusCode.ERROR ? "error" : "ok",
        attributes: { ...s.attributes },
      });
    }
    if (this.spans.length > this.cap) this.spans.splice(0, this.spans.length - this.cap);
    done({ code: 0 });
  }
  shutdown(): Promise<void> {
    return Promise.resolve();
  }
}

export const spanStore = new RingExporter();
const provider = new NodeTracerProvider({ spanProcessors: [new SimpleSpanProcessor(spanStore)] });
provider.register();
export const tracer = trace.getTracer("agentgate");

/** Run `fn` inside a span, recording errors and attributes. */
export async function withSpan<T>(
  name: string,
  attrs: Record<string, string | number | boolean | undefined>,
  fn: (span: Span) => Promise<T>,
): Promise<T> {
  return tracer.startActiveSpan(name, async (span) => {
    for (const [k, v] of Object.entries(attrs)) if (v !== undefined) span.setAttribute(k, v);
    try {
      return await fn(span);
    } catch (err) {
      span.setStatus({ code: SpanStatusCode.ERROR, message: (err as Error).message });
      throw err;
    } finally {
      span.end();
    }
  });
}
