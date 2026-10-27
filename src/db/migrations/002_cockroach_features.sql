-- CockroachDB-specific tuning.

-- Time-range queries over the audit log use a hash-sharded index so sequential timestamps
-- spread across ranges instead of hammering one (the classic monotonic-key hotspot).
CREATE INDEX IF NOT EXISTS audit_ts_idx ON audit_events (ts DESC) USING HASH STORING (tool, decision, agent_id);
CREATE INDEX IF NOT EXISTS audit_agent_idx ON audit_events (tenant_id, agent_id, ts DESC);

-- Row-level TTL: the database deletes expired rows in the background, so retention needs no cron job.
ALTER TABLE audit_events SET (ttl_expiration_expression = '(ts + INTERVAL ''90 days'')', ttl_job_cron = '@daily');
ALTER TABLE auth_codes SET (ttl_expiration_expression = '(expires_at + INTERVAL ''1 hour'')', ttl_job_cron = '@hourly');
ALTER TABLE refresh_tokens SET (ttl_expiration_expression = '(expires_at + INTERVAL ''1 day'')', ttl_job_cron = '@daily');
ALTER TABLE mcp_sessions SET (ttl_expiration_expression = '(last_seen + INTERVAL ''7 days'')', ttl_job_cron = '@daily');
