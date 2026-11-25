-- 072_identity_parent_index.up.sql
-- Two partial indexes on identities, for the registration tree (071):
--
-- idx_identities_parent (account, project, parent): listing an identity's
-- children (GET /identities?parent_identity_id=) and walking its descendants
-- when it is deactivated both filter on all three. Only rows with a parent:
-- the identities nobody registered (every row before 071, and most after) add
-- nothing to it.
--
-- idx_identities_cascade_pending (cascade_pending_at): the cleanup worker's
-- hourly pass lists marked identities oldest first. Only marked rows, which
-- are few and short-lived, so the pass reads the index, not the table.
--
-- LOCK POSTURE (cf. 059/068). Non-CONCURRENT inside golang-migrate's implicit
-- transaction, so writes to identities wait for two scans of the table. A
-- large installation applies 071 and 072 by hand first, then deploys, and
-- both migrations become no-ops. The runner applies each file in one
-- transaction, so it cannot build these CONCURRENTLY itself, and the
-- statements below must not be run through it out of order. The sequence:
--
--   1. Run, on every pod, a release that tolerates columns it does not know
--      (v1.31.0 or later).
--   2. From one session, add 071's columns, retrying on a lock timeout:
--        SET lock_timeout = '3s';
--        ALTER TABLE identities
--            ADD COLUMN IF NOT EXISTS parent_identity_id UUID,
--            ADD COLUMN IF NOT EXISTS cascade_pending_at TIMESTAMPTZ;
--   3. Build both indexes, each statement on its own (CONCURRENTLY cannot run
--      inside a transaction block):
--        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_identities_parent
--            ON identities (account_id, project_id, parent_identity_id)
--            WHERE parent_identity_id IS NOT NULL;
--        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_identities_cascade_pending
--            ON identities (cascade_pending_at)
--            WHERE cascade_pending_at IS NOT NULL;
--      and check that both finished:
--        SELECT c.relname, i.indisvalid FROM pg_index i
--        JOIN pg_class c ON c.oid = i.indexrelid
--        WHERE c.relname IN ('idx_identities_parent', 'idx_identities_cascade_pending');
--      A concurrent build that failed leaves an INVALID index that IF NOT
--      EXISTS would then skip: drop it (DROP INDEX CONCURRENTLY <name>) and
--      build it again.
--   4. Deploy the tree's release. 071 then only swaps the audit trigger
--      (catalog-only), and 072 finds both indexes.
--
-- A failed run of this migration leaves (71, dirty): recover with
-- `migrate force 70`.
SET LOCAL lock_timeout = '5s';

CREATE INDEX IF NOT EXISTS idx_identities_parent
    ON identities (account_id, project_id, parent_identity_id)
    WHERE parent_identity_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_identities_cascade_pending
    ON identities (cascade_pending_at)
    WHERE cascade_pending_at IS NOT NULL;
