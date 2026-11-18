-- 070_identity_parent_index.up.sql
-- Index the registration tree by (account, project, parent): listing an
-- identity's children (GET /identities?parent_identity_id=) and walking its
-- descendants when it is deactivated both filter on all three. Partial, so the
-- identities nobody registered (every row before 069, and most after) add
-- nothing to it.
--
-- LOCK POSTURE (cf. 059/068). Non-CONCURRENT inside golang-migrate's implicit
-- transaction, so writes to identities wait for one scan of the table. Large
-- installations can build it out of band after 069, with
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_identities_parent ON identities (account_id, project_id, parent_identity_id) WHERE parent_identity_id IS NOT NULL;
-- and this migration becomes a no-op. A failed run leaves (70, dirty): recover
-- with `migrate force 69`.
SET LOCAL lock_timeout = '5s';

CREATE INDEX IF NOT EXISTS idx_identities_parent
    ON identities (account_id, project_id, parent_identity_id)
    WHERE parent_identity_id IS NOT NULL;
