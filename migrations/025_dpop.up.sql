-- 025_dpop.up.sql
-- DPoP — Demonstrating Proof of Possession (RFC 9449).
--
-- dpop_jti: proof JTI replay-prevention store.
--   INSERT fails on duplicate primary key → replay detected without a pre-check query.
--   expires_at drives cleanup; rows outside the freshness window are purged by the
--   cleanup worker since a proof that old would fail the iat check before JTI lookup.
--
--   Storage parameters: lowered autovacuum_vacuum_scale_factor (default 0.2) to
--   keep dead tuples reaped at 5% rather than waiting for 20% bloat — under
--   DPoP-heavy load this table sees a high INSERT-then-DELETE churn rate with
--   no UPDATEs, which is exactly the workload where 0.05 helps the most.
--   fillfactor=90 leaves some page headroom for the rare row-version update.
--
-- issued_credentials.dpop_key_thumbprint: base64url JWK thumbprint (RFC 7638 SHA-256)
--   of the DPoP key bound to this credential (RFC 9449 §6.1). NULL for Bearer tokens.
--
-- Lock posture: ALTER TABLE on issued_credentials is metadata-only on PG 11+
-- (nullable column, no default, no rewrite). CREATE TABLE / CREATE INDEX are
-- on a brand-new empty table so no concurrent-rebuild concern. lock_timeout
-- below scopes any blocking-acquire to a safe failure path.

SET LOCAL lock_timeout = '3s';

CREATE TABLE IF NOT EXISTS dpop_jti (
    jti        VARCHAR(512) PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
) WITH (fillfactor = 90, autovacuum_vacuum_scale_factor = 0.05);

CREATE INDEX IF NOT EXISTS idx_dpop_jti_expires_at ON dpop_jti (expires_at);

ALTER TABLE issued_credentials
    ADD COLUMN IF NOT EXISTS dpop_key_thumbprint TEXT;
