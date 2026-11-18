-- 069_identity_parent.up.sql
-- Record which identity registered an identity.
--
-- When the embedding service authenticates an admin request as a registered
-- identity acting as itself (zeroid.WithCallerIdentity), an identity created by
-- that request stores the caller's id here. The column is the edge of the
-- registration tree: a child is bound by its parent's scope ceilings, and
-- deactivating an identity deactivates every identity below it. See
-- docs/identity-tree.md.
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
-- DDL ONLY, like 045. The index is 070, in its own file: golang-migrate runs
-- each file as one implicit transaction, so building the index here would hold
-- this ALTER's ACCESS EXCLUSIVE lock on identities, blocking every read and
-- write, for the whole table scan.
--
-- Lock posture: nullable, no default, so a metadata-only ADD COLUMN on PG 11+,
-- held for well under a millisecond once acquired. The risk is the lock queue
-- behind in-flight transactions, hence lock_timeout. A timeout abort leaves
-- schema_migrations at (69, dirty); recover with `migrate force 68` and run it
-- again.
SET LOCAL lock_timeout = '3s';

ALTER TABLE identities
    ADD COLUMN IF NOT EXISTS parent_identity_id UUID;
