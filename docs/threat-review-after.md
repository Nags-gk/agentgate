# Security design review: AgentGate (after review fixes)

MCP gateway on Cloud Run. AI clients (Claude, Cursor, service agents) authenticate with OAuth 2.1 and call scoped tools; the gateway decrypts upstream credentials from its vault per call and talks to GitHub, Slack and Jira, or to third-party MCP servers in a local sandbox. State, policy and the hash-chained audit log live in CockroachDB.


**Open findings:** 5 (4 critical, 1 medium) · **Accepted risks:** 1

## Data-flow diagram

Dashed edges are plaintext or unauthenticated hops; red components carry open high or critical findings.

```mermaid
flowchart LR
  subgraph z_internet["internet (trust 0)"]
    ai_client(["ai_client<br/><small>client</small>"])
    admin_ui["admin_ui<br/><small>admin_console</small>"]
  end
  subgraph z_sandbox["sandbox (trust 1)"]
    sandboxed_mcp{{"sandboxed_mcp<br/><small>third_party</small>"}}
  end
  subgraph z_saas["saas (trust 2)"]
    saas_apis{{"saas_apis<br/><small>third_party</small>"}}
  end
  subgraph z_gcp_app["gcp_app (trust 3)"]
    gateway["gateway<br/><small>gateway</small>"]
    oauth_server["oauth_server<br/><small>identity_provider</small>"]
    agent_quarantine["agent_quarantine<br/><small>detection</small>"]
  end
  subgraph z_gcp_managed["gcp_managed (trust 3)"]
    secret_manager[("secret_manager<br/><small>datastore</small>")]
  end
  subgraph z_managed_db["managed_db (trust 4)"]
    cockroachdb[("cockroachdb<br/><small>datastore</small>")]
    audit_log[("audit_log<br/><small>log_sink</small>")]
  end
  ai_client -->|"https / oauth2"| gateway
  ai_client -->|"https / password"| oauth_server
  admin_ui -->|"https / session"| gateway
  gateway -->|"https / api_key"| saas_apis
  gateway -.->|"internal_tls / none"| sandboxed_mcp
  gateway -->|"sql_tls / password"| cockroachdb
  gateway -->|"sql_tls / password"| audit_log
  gateway -->|"https / workload_identity"| secret_manager
  style gateway stroke:#d93025,stroke-width:3px
  style oauth_server stroke:#d93025,stroke-width:3px
```

## Findings

| Risk | Rating | ID | Element | STRIDE | Lens | Finding |
|---:|---|---|---|---|---|---|
| 25 | critical | TL-A02 | `gateway` | Spoofing | abuse | Login lacks credential-stuffing defenses |
| 25 | critical | TL-A02 | `oauth_server` | Spoofing | abuse | Login lacks credential-stuffing defenses |
| 25 | critical | TL-S02 | `gateway` | Spoofing | access | Internet-facing login without multi-factor authentication |
| 25 | critical | TL-S02 | `oauth_server` | Spoofing | access | Internet-facing login without multi-factor authentication |
| 8 | medium | TL-S05 | `f_upstream` | Spoofing | access | Service-to-service call uses a static API key |

## Recommended changes: access

- **TL-S02 on `gateway` (critical).** A leaked or phished password is enough to take over an account. **Change:** Offer and default to a second factor (passkeys or TOTP); require it on new devices and for sensitive changes. _(CWE-308 Use of Single-factor Authentication · T1078 Valid Accounts)_
- **TL-S02 on `oauth_server` (critical).** A leaked or phished password is enough to take over an account. **Change:** Offer and default to a second factor (passkeys or TOTP); require it on new devices and for sensitive changes. _(CWE-308 Use of Single-factor Authentication · T1078 Valid Accounts)_
- **TL-S05 on `f_upstream` (medium).** Long-lived shared keys leak through logs, configs and laptops and rarely get rotated. **Change:** Use workload identity or mTLS with short-lived certificates between services. _(CWE-798 Use of Hard-coded Credentials)_

## Recommended changes: abuse

- **TL-A02 on `gateway` (critical).** Leaked combo lists are replayed across the user base until reused passwords hit. **Change:** Check passwords against breach corpora, add bot detection, and step up on never-seen devices and hosting ASNs. _(CWE-307 Improper Restriction of Excessive Authentication Attempts · T1110.004 Credential Stuffing)_
- **TL-A02 on `oauth_server` (critical).** Leaked combo lists are replayed across the user base until reused passwords hit. **Change:** Check passwords against breach corpora, add bot detection, and step up on never-seen devices and hosting ASNs. _(CWE-307 Improper Restriction of Excessive Authentication Attempts · T1110.004 Credential Stuffing)_

## Accepted risks

- TL-S01 on `f_sandbox`: Unauthenticated flow crosses a trust boundary. Justification: stdio pipe to a child process on the same host; isolation comes from the Node permission model and egress guard, not from network auth
