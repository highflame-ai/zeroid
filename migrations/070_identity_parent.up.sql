-- 070_identity_parent.up.sql
-- Record which identity registered an identity, and mark a deactivation
-- cascade that has not finished.
--
-- parent_identity_id: when the embedding service authenticates an admin
-- request as a registered identity acting as itself
-- (zeroid.WithCallerIdentity), an identity created by that request stores the
-- caller's id here. The column is the edge of the registration tree: a child
-- is bound by its parent's ceilings, receives no token while an identity
-- above it is not active, and deactivating an identity deactivates every
-- identity below it. See docs/identity-tree.md.
--
-- NULL means the identity was not registered by an identity: every row that
-- exists before this migration, and every identity an admin or a discovery
-- connector registers. There is no backfill.
--
-- No foreign key. Identities are soft-deleted (status = deactivated), so a
-- parent row is never removed in normal operation, and the write path already
-- resolves the parent inside the child's own account and project under a row
-- lock. A key on id alone could not express that tenant rule, and its
-- delete-time check would scan identities on every hard delete.
--
-- cascade_pending_at: set in the same UPDATE that retires an identity
-- (deactivated or expired), and on each identity the cascade then
-- deactivates; cleared once the walk below it, or its own cleanup, has
-- finished. The cleanup worker and a repeated deactivation resume every
-- identity still marked, so a walk cut short by a crash or a failed step
-- finishes. NULL for every existing row. Not indexed: the worker reads it once
-- per pass (hourly).
--
-- The identity audit trigger (066) is redefined to ignore cascade_pending_at,
-- like updated_at and modified_by, so setting and clearing the mark writes no
-- audit row of its own.
--
-- DDL ONLY, like 045. The index is 071, in its own file: golang-migrate runs
-- each file as one implicit transaction, so building the index here would hold
-- this ALTER's ACCESS EXCLUSIVE lock on identities, blocking every read and
-- write, for the whole table scan.
--
-- Lock posture: both columns nullable, no default, so a metadata-only ADD
-- COLUMN on PG 11+, and the trigger swap is catalog-only; the lock is held for
-- well under a millisecond once acquired. The risk is the lock queue behind
-- in-flight transactions, hence lock_timeout. A timeout abort leaves
-- schema_migrations at (70, dirty); recover with `migrate force 69` and run it
-- again.
SET LOCAL lock_timeout = '3s';

ALTER TABLE identities
    ADD COLUMN IF NOT EXISTS parent_identity_id UUID,
    ADD COLUMN IF NOT EXISTS cascade_pending_at TIMESTAMPTZ;

DROP TRIGGER IF EXISTS identity_audit_update_trigger ON identities;
CREATE TRIGGER identity_audit_update_trigger
    AFTER UPDATE ON identities
    FOR EACH ROW
    WHEN ((to_jsonb(OLD) - 'updated_at' - 'modified_by' - 'cascade_pending_at') IS DISTINCT FROM (to_jsonb(NEW) - 'updated_at' - 'modified_by' - 'cascade_pending_at'))
    EXECUTE FUNCTION create_identity_audit_log();
