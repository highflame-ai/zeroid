-- 017_time_bound_authority.up.sql
-- Adds expires_at to identities and credential_policies so the grant of
-- authority itself can be time-bound, not just the JWTs it issues.
-- service_keys.expires_at already exists (migration 006); this migration
-- only adds the matching partial index so the expiring-soon endpoint can
-- scan the same way across all three tables.
--
-- All three columns are nullable. NULL means "no expiry" — the existing
-- forever-live default. The cleanup worker only sweeps rows with a
-- non-NULL expires_at past now(), so existing rows are untouched.

ALTER TABLE identities          ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE credential_policies ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

-- Partial indexes for the cleanup-worker sweep and the /expiring-soon
-- admin endpoint. WHERE clause keeps the index small — the common case
-- is unbounded grants (expires_at IS NULL) and those rows never qualify.
--
-- These are plain CREATE INDEX (not CONCURRENTLY) because golang-migrate
-- wraps each migration in a transaction and CONCURRENTLY can't run
-- inside one. The partial WHERE clauses limit the scan to rows where
-- expires_at IS NOT NULL — zero rows on first deploy, so the build is
-- effectively instant regardless of identities/credential_policies/
-- service_keys row count. Existing large deployments that later backfill
-- expires_at should expect rebuild cost proportional to the number of
-- time-bound rows, not the full table.
--
-- The three tables use three different "active" column names — status,
-- is_active, state — for historical reasons. Each index mirrors its
-- table's convention; do not unify here.
CREATE INDEX IF NOT EXISTS idx_identities_expiring
    ON identities (expires_at)
    WHERE expires_at IS NOT NULL AND status = 'active';

CREATE INDEX IF NOT EXISTS idx_credential_policies_expiring
    ON credential_policies (expires_at)
    WHERE expires_at IS NOT NULL AND is_active = TRUE;

CREATE INDEX IF NOT EXISTS idx_service_keys_expiring
    ON service_keys (expires_at)
    WHERE expires_at IS NOT NULL AND state = 'active';
