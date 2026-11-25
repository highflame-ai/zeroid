-- 071_identity_parent_index.up.sql
-- Index the registration tree by (account, project, parent): listing an
-- identity's children (GET /identities?parent_identity_id=) and walking its
-- descendants when it is deactivated both filter on all three. Partial, so the
-- identities nobody registered (every row before 070, and most after) add
-- nothing to it.
--
-- LOCK POSTURE (cf. 059/068). Non-CONCURRENT inside golang-migrate's implicit
-- transaction, so writes to identities wait for one scan of the table. Large
-- installations can build it out of band after 070, with
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_identities_parent ON identities (account_id, project_id, parent_identity_id) WHERE parent_identity_id IS NOT NULL;
-- run from one session (CONCURRENTLY cannot run inside a transaction block),
-- and this migration becomes a no-op. Check the build finished before
-- deploying:
--   SELECT indisvalid FROM pg_index WHERE indexrelid = 'idx_identities_parent'::regclass;
-- A concurrent build that failed leaves an INVALID index that IF NOT EXISTS
-- would then skip: drop it (DROP INDEX CONCURRENTLY idx_identities_parent)
-- and build it again. A failed run of this migration leaves (71, dirty):
-- recover with `migrate force 70`.
--
-- The down is the single statement DROP INDEX CONCURRENTLY, so golang-migrate
-- sends it alone, outside a transaction, and dropping the index blocks no
-- writes.
SET LOCAL lock_timeout = '5s';

CREATE INDEX IF NOT EXISTS idx_identities_parent
    ON identities (account_id, project_id, parent_identity_id)
    WHERE parent_identity_id IS NOT NULL;
