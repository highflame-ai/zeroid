-- 034_id_jag_jti.up.sql
-- ID-JAG single-use replay-prevention store (ADR 0010 D2a).
--
-- An MCP ID-JAG (Identity Assertion Authorization Grant) is a single-use
-- authorization grant — auth-code-like, not a reusable bearer token. Its `jti`
-- MUST be consumed exactly once: a second redemption of the same `jti` is a
-- replay and MUST be rejected (OAuth invalid_grant).
--
-- id_jag_jti: redeemed-jti ledger.
--   INSERT fails on duplicate primary key (SQLSTATE 23505) → replay detected
--   without a pre-check query (atomic check-and-insert; no TOCTOU).
--   expires_at is the ID-JAG's own exp; rows outside that window are purged by
--   the cleanup worker since a grant that old would fail its exp check before
--   the jti is ever consumed.
--
--   Schema mirrors dpop_jti (migration 025_dpop) verbatim — same single-use
--   replay-table shape, same storage tuning. Storage parameters: lowered
--   autovacuum_vacuum_scale_factor (default 0.2) to keep dead tuples reaped at
--   5% rather than waiting for 20% bloat — this table sees high INSERT-then-
--   DELETE churn with no UPDATEs, exactly the workload where 0.05 helps most.
--   fillfactor=90 leaves some page headroom for the rare row-version update.
--
-- Lock posture: CREATE TABLE / CREATE INDEX are on a brand-new empty table so
-- there is no concurrent-rebuild concern. lock_timeout below scopes any
-- blocking-acquire to a safe failure path.

SET LOCAL lock_timeout = '3s';

CREATE TABLE IF NOT EXISTS id_jag_jti (
    jti        VARCHAR(512) PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
) WITH (fillfactor = 90, autovacuum_vacuum_scale_factor = 0.05);

CREATE INDEX IF NOT EXISTS idx_id_jag_jti_expires_at ON id_jag_jti (expires_at);
