-- 070_identity_parent_index.down.sql
SET LOCAL lock_timeout = '5s';

DROP INDEX IF EXISTS idx_identities_parent;
