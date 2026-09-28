-- 045_identity_adopted_at.up.sql
-- Record WHEN a discovered identity was adopted, so the registry can list
-- adopted agents newest-adoption-first.
--
-- The registry lists by created_at DESC. For a discovered identity created_at is
-- when a connector sync first SAW it, not when a human adopted it, so adopted
-- agents land wherever they were discovered — often months back — and the list
-- reads as random. updated_at is no substitute: reconcileDiscovered bumps it on
-- every sync (it doubles as the prune "last seen" marker), so ordering on it
-- would reshuffle the list after each sync.
--
-- Set by UpdateIdentity on discovered → pending|active, cleared when an
-- adoption is reverted (DismissIdentity, pending → discovered). NULL for native
-- identities and anything never adopted; the list orders by
-- COALESCE(adopted_at, created_at), so those keep their creation time.
--
-- DDL ONLY. The backfill is 046, deliberately in its own file: golang-migrate
-- runs each file as one implicit transaction, so a backfill here would hold
-- this ALTER's ACCESS EXCLUSIVE lock on identities — blocking every read and
-- write — for the whole scan of identity_audit_logs, which grows with every
-- connector sync and has no index that serves it.
--
-- Lock posture: nullable, no default → metadata-only ADD COLUMN on PG 11+,
-- held for well under a millisecond once acquired. The risk is the lock QUEUE
-- behind in-flight transactions, hence lock_timeout (044's precedent). A
-- timeout abort leaves schema_migrations at (45, dirty) and, with AutoMigrate
-- on, every pod then fails startup: stage `migrate force 44` in the runbook.
--
-- Post-migration check: ADD COLUMN IF NOT EXISTS silently no-ops against a
-- same-named column of another type, so assert udt_name = 'timestamptz'.
SET LOCAL lock_timeout = '3s';

ALTER TABLE identities
    ADD COLUMN IF NOT EXISTS adopted_at TIMESTAMPTZ;
