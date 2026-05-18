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
-- admin endpoint. WHERE clause keeps the index *small* — but does NOT
-- shrink the build scan. Postgres reads every row in the table to
-- evaluate the partial-index predicate; the savings are in storage and
-- query plans, not in build time.
--
-- These are plain CREATE INDEX (not CONCURRENTLY) because golang-migrate
-- wraps each migration in a transaction and CONCURRENTLY can't run
-- inside one. CREATE INDEX takes ShareLock for the build duration,
-- blocking writes (reads continue). Build cost is proportional to total
-- row count, not just to expires_at-IS-NOT-NULL row count.
--
-- Concrete cost shape:
--   identities, credential_policies: brand-new columns, every row's
--     expires_at IS NULL, so the partial predicate excludes every row
--     from the index payload — the build still scans, but the resulting
--     index occupies near-zero storage. Lock window scales with table
--     size; for tables in the millions of rows expect seconds-to-minutes.
--   service_keys: expires_at predates this migration and may already
--     be populated on existing deployments. The index payload reflects
--     those rows, and the build scans the whole table. Operators with
--     large service_keys should plan a maintenance window or move this
--     index out of the transaction (rerun manually with CONCURRENTLY).
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
