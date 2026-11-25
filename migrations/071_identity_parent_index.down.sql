-- 071_identity_parent_index.down.sql
-- Not CONCURRENTLY: that drops one index per statement and only outside a
-- transaction, and the runner sends this file as one. Dropping an index is
-- catalog-only, so the lock is held briefly once acquired; lock_timeout keeps
-- it from queueing behind long transactions.
SET LOCAL lock_timeout = '3s';

DROP INDEX IF EXISTS idx_identities_cascade_pending;
DROP INDEX IF EXISTS idx_identities_parent;
