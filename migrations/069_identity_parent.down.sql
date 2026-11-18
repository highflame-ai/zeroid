-- 069_identity_parent.down.sql
-- No-op: the column is kept. Dropping it would discard every recorded
-- registration edge, which re-applying 069 could not restore. Keeping it is
-- safe for a rolled-back binary: bun names model columns explicitly, so a
-- binary that predates parent_identity_id never reads it and inserts NULL.
-- 069's up is idempotent (ADD COLUMN IF NOT EXISTS), so re-applying it after a
-- revert is a no-op.
SELECT 1;
