-- AgentGate schema for CockroachDB (v24.1+).
-- Every tenant-owned table is keyed by (tenant_id, ...) so one tenant's rows sit together
-- and a query can never forget the tenant filter without failing the primary-key lookup.

CREATE TABLE IF NOT EXISTS tenants (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  slug       STRING NOT NULL UNIQUE,
  name       STRING NOT NULL,
  -- Data-classification labels for resources, e.g. {"labels": {"slack:#ext-*": "public"}}
  settings   JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
  tenant_id     UUID NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  id            UUID NOT NULL DEFAULT gen_random_uuid(),
  email         STRING NOT NULL,
  display_name  STRING NOT NULL,
  password_hash STRING NOT NULL,
  is_admin      BOOL NOT NULL DEFAULT false,
  groups        STRING[] NOT NULL DEFAULT ARRAY[]::STRING[],
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (email)
);

-- A bundle is a virtual MCP server: the tools (and argument constraints) a role or agent may use.
CREATE TABLE IF NOT EXISTS bundles (
  tenant_id   UUID NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  id          STRING NOT NULL,
  name        STRING NOT NULL,
  description STRING NOT NULL DEFAULT '',
  rules       JSONB NOT NULL,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id)
);

-- Which bundles a group of users may grant. A user's ceiling is the union over their groups.
CREATE TABLE IF NOT EXISTS group_bundles (
  tenant_id UUID NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  grp       STRING NOT NULL,
  bundle_id STRING NOT NULL,
  PRIMARY KEY (tenant_id, grp, bundle_id)
);

-- Service agents (long-running, machine-to-machine). They act for an owner and are capped
-- by both the owner's ceiling and their own bundle.
CREATE TABLE IF NOT EXISTS agents (
  tenant_id     UUID NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  id            UUID NOT NULL DEFAULT gen_random_uuid(),
  name          STRING NOT NULL,
  owner_user_id UUID NOT NULL,
  bundle_id     STRING NOT NULL,
  disabled      BOOL NOT NULL DEFAULT false,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id      STRING PRIMARY KEY,
  tenant_id      UUID,
  name           STRING NOT NULL,
  redirect_uris  STRING[] NOT NULL DEFAULT ARRAY[]::STRING[],
  secret_hash    STRING,
  agent_id       UUID,
  grant_types    STRING[] NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS auth_codes (
  code_hash      STRING PRIMARY KEY,
  client_id      STRING NOT NULL,
  tenant_id      UUID NOT NULL,
  user_id        UUID NOT NULL,
  bundle_id      STRING NOT NULL,
  redirect_uri   STRING NOT NULL,
  code_challenge STRING NOT NULL,
  resource       STRING NOT NULL,
  expires_at     TIMESTAMPTZ NOT NULL,
  used           BOOL NOT NULL DEFAULT false
);

-- Refresh tokens rotate on every use. Tokens share a family; presenting an already-rotated
-- token (a replay) revokes the whole family.
CREATE TABLE IF NOT EXISTS refresh_tokens (
  token_hash STRING PRIMARY KEY,
  family_id  UUID NOT NULL,
  client_id  STRING NOT NULL,
  tenant_id  UUID NOT NULL,
  user_id    UUID NOT NULL,
  bundle_id  STRING NOT NULL,
  resource   STRING NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  rotated    BOOL NOT NULL DEFAULT false,
  revoked    BOOL NOT NULL DEFAULT false,
  INDEX (family_id)
);

CREATE TABLE IF NOT EXISTS revoked_families (
  family_id  UUID PRIMARY KEY,
  revoked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Upstream credentials, envelope-encrypted: a random data key per row (AES-256-GCM),
-- wrapped by a versioned key-encryption key that never touches the database.
CREATE TABLE IF NOT EXISTS credentials (
  tenant_id   UUID NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  id          UUID NOT NULL DEFAULT gen_random_uuid(),
  user_id     UUID,
  connector   STRING NOT NULL,
  ciphertext  BYTES NOT NULL,
  wrapped_key BYTES NOT NULL,
  kek_version INT8 NOT NULL,
  scopes      STRING[] NOT NULL DEFAULT ARRAY[]::STRING[],
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  rotated_at  TIMESTAMPTZ,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, user_id, connector)
);

CREATE TABLE IF NOT EXISTS signing_keys (
  kid         STRING PRIMARY KEY,
  private_enc BYTES NOT NULL,
  wrapped_key BYTES NOT NULL,
  kek_version INT8 NOT NULL,
  public_jwk  JSONB NOT NULL,
  active      BOOL NOT NULL DEFAULT true,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Data-flow state per MCP session: the sensitivity labels of everything the agent has read.
CREATE TABLE IF NOT EXISTS mcp_sessions (
  tenant_id  UUID NOT NULL,
  id         STRING NOT NULL,
  user_id    UUID NOT NULL,
  agent_id   UUID,
  client_id  STRING NOT NULL,
  bundle_id  STRING NOT NULL,
  level      INT8 NOT NULL DEFAULT 0,
  -- Resources whose content was flagged as a prompt injection in this session.
  untrusted  STRING[] NOT NULL DEFAULT ARRAY[]::STRING[],
  sources    STRING[] NOT NULL DEFAULT ARRAY[]::STRING[],
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id)
);

-- Tamper-evident audit log. Each event stores the hash of the previous event in its
-- tenant's chain; audit_heads holds the chain tip and is updated in the same transaction.
CREATE TABLE IF NOT EXISTS audit_events (
  tenant_id     UUID NOT NULL,
  seq           INT8 NOT NULL,
  id            UUID NOT NULL DEFAULT gen_random_uuid(),
  ts            TIMESTAMPTZ NOT NULL DEFAULT now(),
  user_id       UUID,
  agent_id      UUID,
  client_id     STRING,
  session_id    STRING,
  bundle_id     STRING,
  connector     STRING NOT NULL,
  tool          STRING NOT NULL,
  action        STRING NOT NULL,
  decision      STRING NOT NULL,
  reason        STRING NOT NULL,
  args_redacted JSONB,
  findings      JSONB,
  flow          JSONB,
  latency_ms    INT8,
  result_bytes  INT8,
  trace_id      STRING,
  prev_hash     STRING NOT NULL,
  hash          STRING NOT NULL,
  PRIMARY KEY (tenant_id, seq)
);

CREATE TABLE IF NOT EXISTS audit_heads (
  tenant_id UUID PRIMARY KEY,
  seq       INT8 NOT NULL,
  hash      STRING NOT NULL
);

CREATE TABLE IF NOT EXISTS redteam_runs (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  agent      STRING NOT NULL,
  report     JSONB NOT NULL
);
