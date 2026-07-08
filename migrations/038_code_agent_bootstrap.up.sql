-- 038: code-agent bootstrap — columns supporting per-machine registration of
-- developer-workstation code agents (highflame-architecture#136, epic #132 S3).
--
-- A code agent (Claude Code, Cursor, ...) bootstraps from a developer machine
-- with a zeroid:bootstrap-scoped token: registration records WHICH machine the
-- agent's custody key lives on (`bootstrap_machine_id`), so operators can
-- revoke every agent from a lost/compromised laptop in one call
-- (revoke-by-machine). `last_attested_at` + `attestation_evidence` track
-- attestation freshness: the agent periodically re-attests its runtime
-- environment and policy can later gate on staleness.
--
-- Additive-only; no backfill needed — NULL bootstrap_machine_id simply means
-- "not a bootstrapped code agent" (every pre-existing row).
--
-- identities is on every auth path and the whole file runs as one implicit
-- transaction (simple query protocol), so the ALTER's AccessExclusiveLock is
-- held through the index build. Fail fast rather than queueing the auth plane
-- behind a long-running query.
-- SET LOCAL: scoped to this file's implicit transaction, so the timeout does
-- not leak onto the migration connection for later files.
SET LOCAL lock_timeout = '5s';

ALTER TABLE identities ADD COLUMN IF NOT EXISTS bootstrap_machine_id VARCHAR(255);
ALTER TABLE identities ADD COLUMN IF NOT EXISTS last_attested_at TIMESTAMPTZ;
ALTER TABLE identities ADD COLUMN IF NOT EXISTS attestation_evidence JSONB;

-- Revoke-by-machine and per-machine listing filter on (account_id,
-- bootstrap_machine_id). Partial: only bootstrapped code agents carry a
-- machine id, so the index stays O(code-agent-rows), not O(all-identities).
CREATE INDEX IF NOT EXISTS idx_identities_bootstrap_machine ON identities (account_id, bootstrap_machine_id) WHERE bootstrap_machine_id IS NOT NULL;

-- Structural guard for the partial index's IS NOT NULL semantics: the model's
-- nullzero tag maps empty Go strings to NULL, but one service-layer UPDATE
-- writes the column raw — make "empty string" impossible at the schema level
-- so a missed validation can never plant a row that matches machine listings.
-- NULL passes the CHECK (NULL <> '' is not false). NOT VALID skips the
-- validation scan entirely — every pre-038 row is NULL for this column, so
-- validation would be vacuous, and new writes are checked regardless.
ALTER TABLE identities ADD CONSTRAINT identities_bootstrap_machine_id_not_empty
    CHECK (bootstrap_machine_id <> '') NOT VALID;
