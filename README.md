# AgentGate

[![ci](https://github.com/Nags-gk/agentgate/actions/workflows/ci.yml/badge.svg)](https://github.com/Nags-gk/agentgate/actions/workflows/ci.yml)

**An MCP gateway that lets AI agents use company tools without inheriting their user's keys.**

**Live demo: LIVE_URL** (simulated GitHub, Slack and Jira; one-click demo accounts)

An agent that holds a user's GitHub, Slack and Jira tokens can do everything that user can, and so can anyone who leaks that token or slips instructions into a ticket the agent reads. AgentGate sits between agents and those systems:

- **Scoped access.** Each agent gets a *bundle*: the tools, resources and argument limits its job needs. A call passes only if both the user's role and the agent's bundle allow it.
- **No credentials in agents.** Upstream tokens are envelope-encrypted in a vault and injected per call. Agents hold short-lived, audience-bound OAuth tokens.
- **Data-flow rules.** A session that has read confidential data cannot write it somewhere public, and a session that has read a prompt injection cannot push anything outside the company.
- **Evidence.** Every call, and every sign-in, consent and policy change, goes into a hash-chained audit log in CockroachDB that detects edits.

![Playground: the same compromised agent with raw tokens and through AgentGate](docs/images/playground.png)

## Results

**Red team.** Six attack scenarios and three normal tasks run twice: once with the agent holding raw tokens, once through the gateway. The agent is scripted to obey every instruction it reads (a fully compromised model). Run it with `npx tsx eval/redteam.ts`.

| | Raw tokens | Through AgentGate |
|---|---|---|
| Attacks that succeeded | 6 of 6 | **0 of 6** |
| Normal tasks completed | 3 of 3 | **3 of 3** |
| Legitimate task still done during an attack | 6 of 6 | 5 of 6 |

The one lost task is deliberate: in the "full engineering role" scenario the injected instructions pull a confidential config into the session, so the no-write-down rule then refuses the agent's internal Jira write too. The same suite runs a real Gemini agent via the `eval-gemini` workflow.

**Gateway overhead** (`eval/bench.ts`; gateway, CockroachDB and simulated upstream on one 2-vCPU host):

| | Before tuning | After |
|---|---|---|
| Added latency per call, p50 / p95 | 24.9 / 36.8 ms | **9.0 / 12.4 ms** |
| Throughput, 8 concurrent sessions | 49 calls/s | **199 calls/s** |

OpenTelemetry spans showed that the upstream call took about 0.9 ms and the rest was database round trips. The fixes were:
- Audit appends became one round trip per batch: a data-modifying CTE advances the chain head only if it is where this instance expects, and the INSERT runs only if that matched.
- Concurrent appends are group-committed.
- Policy lookups are cached for 5 s.
- Session labels live in memory for sessions this instance serves.

**Threat model of itself.** I reviewed AgentGate with [ThreatLens](https://github.com/Nags-gk/threatlens), my threat-modeling tool:
- **As built:** 8 open findings ([review](docs/threat-review-before.md)).
- **Fixed:** login throttling, authentication and admin events in the audit chain, signing-key rotation, and a detector that quarantines an agent after repeated blocked calls ([review](docs/threat-review-after.md)).
- **Still open:** the four password-login criticals, by design for a public demo with shared passwords. The production answer is delegating sign-in to the company's identity provider (SSO), which is not built yet.

## How a call flows

```mermaid
flowchart LR
  A[Agent: Claude, Cursor,\nservice agent] -->|OAuth 2.1 bearer\naudience = /mcp| G
  subgraph G[AgentGate]
    direction TB
    V[verify token\nES256, audience, revocation] --> R[rate limit]
    R --> P[policy\nrole AND bundle]
    P --> S[secrets in write args?]
    S --> F[data-flow rules\nsession labels]
    F --> U[decrypt credential\ncall upstream]
    U --> X[redact secrets\nflag injections]
    X --> L[audit chain\nCockroachDB]
  end
  U --> GH[GitHub]
  U --> SL[Slack]
  U --> JI[Jira]
  U --> SB[sandboxed\nstdio MCP server]
```

| Layer | What it does | Where |
|---|---|---|
| OAuth 2.1 server | MCP authorization spec: RFC 9728 and 8414 discovery, RFC 7591 dynamic client registration, code + PKCE (S256 only), RFC 8707 resource indicators, refresh-token rotation with reuse detection, `client_credentials` for service agents, RFC 9207 `iss` | `src/auth/` |
| Policy | Bundles are virtual MCP servers. Tool and resource globs plus argument limits; effective access = user ceiling AND token grant; tools outside it are not even listed | `src/policy.ts` |
| Data flow | Levels public < internal < confidential < restricted per resource. No write-down; after a flagged injection, no high-risk tools and no writes to public destinations except back to the source | `src/policy.ts` |
| Guard | Redacts 11 credential formats in results, blocks writes whose arguments carry one, flags 7 injection patterns (hidden HTML comments, invisible Unicode, instructions addressed to AI agents) | `src/guard/scan.ts` |
| Vault | AES-256-GCM per secret with a random data key, wrapped by a versioned key-encryption key; associated data binds each ciphertext to its row; KEK rotation re-wraps keys only | `src/vault.ts` |
| Sandbox | Third-party stdio MCP servers run under Node's permission model (read only their own directory, no writes, child processes, workers, addons or raw bindings) plus a frozen egress allowlist; the test server's 10 escape attempts all fail | `src/connectors/sandbox.ts` |
| Audit | Per-tenant SHA-256 hash chain, one-round-trip group commit, verify and NDJSON export | `src/audit.ts` |
| Detection | Quarantines an agent after 8 blocked calls in 10 minutes (disable + revoke + audit event) | `src/security.ts` |
| Insights | Blast radius per agent: raw-token reach against gateway reach, and granted-but-unused tools from 30 days of audit data | `src/insights.ts` |
| Observability | OpenTelemetry spans (shown in the console), Prometheus metrics, structured audit | `src/telemetry.ts` |

### CockroachDB specifics

- Tenant-prefixed primary keys.
- A hash-sharded index on audit timestamps, so time-ordered writes don't pile onto one range.
- Row-level TTL for retention: audit 90 days, auth codes, refresh tokens, sessions.
- SERIALIZABLE transactions with a client-side retry loop on SQLSTATE 40001.
- The audit head is advanced with an optimistic conditional UPDATE inside a CTE.

## Use it

**Claude Code:** `claude mcp add --transport http agentgate LIVE_URL/mcp`, then `/mcp` to sign in. Pick `dana@acme.test` / `agentgate-demo` and a bundle.

**Unattended agent:** create one on the Agents page, then:

```bash
curl -u CLIENT_ID:CLIENT_SECRET -d grant_type=client_credentials LIVE_URL/oauth/token
```

## Run it locally

```bash
cockroach start-single-node --insecure --background     # or: docker run -p 26257:26257 cockroachdb/cockroach:v25.2.0 start-single-node --insecure
cockroach sql --insecure -e "CREATE DATABASE agentgate"
npm ci && npm ci --prefix web && npm run build --prefix web
npm start                                               # http://localhost:8080, demo mode by default
npm test                                                # 43 tests against a real CockroachDB
npx tsx eval/redteam.ts                                 # red-team suite
GEMINI_API_KEY=... npx tsx eval/redteam.ts --agent gemini
```

Configuration lives in `src/config.ts`:
- `DATABASE_URL`, `PUBLIC_URL`.
- `VAULT_KEKS` (`version:base64key,...`).
- `DEMO_MODE`.
- `GEMINI_API_KEY`.
- `RATE_LIMIT_PER_MIN`, `METRICS_TOKEN`.

## Tests

There are 43 tests, and CI runs them against a real CockroachDB:
- **Unit:** policy intersection and argument limits, flow rules, the guard (including false positives on ordinary engineering text), the vault (tamper, wrong row, KEK rotation), PKCE, redirect-URI validation, rate limiting.
- **OAuth integration:** single-use codes, wrong verifier, foreign resource, a bundle outside the user's role, refresh-token replay revoking the family.
- **MCP integration:** scoped tool lists, injection flagging, redaction, flow blocks, session hijack refused, agent disable revoking live tokens.
- **Audit:** the chain stays intact under 25 concurrent appends, and an edit is detected.
- **Sandbox:** escape attempts.
- **Red-team suite:** run as part of the tests.
- **Client conformance:** the official MCP SDK OAuth client discovers, registers and completes sign-in on its own, as Claude Code does.

## Honest limits

- **The demo is simulated.** It runs against simulated GitHub, Slack and Jira APIs: the same paths and response shapes, and the connectors are the real ones, but no real workspace is behind them. Real connectors need per-user OAuth tokens (brokered OAuth is not built yet).
- **The scripted agent is a worst case, not a measurement of a real model.** Gemini results come from the `eval-gemini` workflow.
- **The injection guard is pattern-based.** It catches the common forms; the data-flow rules are what hold when it misses.
- **Single-instance assumptions.** Rate limiting, login throttling and the session queue are per instance; the demo runs one Cloud Run instance. Policy changes reach other instances within 5 s.
- **The sandbox is the Node permission model plus an egress guard.** On Cloud Run that runs inside gVisor; it is not a substitute for a VM boundary for hostile native code.
- **Benchmark scope.** The numbers are from one host with a single CockroachDB node, not a multi-region cluster.

## How it was built

The project was built in a few sessions with Claude Code. I made the design calls:
- **Two-bundle intersection:** access is the user's role AND the agent's bundle.
- **No write-down after a flagged read:** confidential data cannot flow to public destinations.
- **Group-commit audit chain.**
- **A test for every claim in this README.**

The tests caught real mistakes along the way:
- Postgres-style interval parameters that CockroachDB rejects.
- An audit hash computed over keys that JSONB later drops.
- An untrusted-content rule so strict it broke normal triage.

MIT licensed.
