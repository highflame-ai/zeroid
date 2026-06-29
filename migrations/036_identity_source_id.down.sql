-- Revert 036: drop the source_id column + its index. Dropping the column also
-- drops the partial index, but the explicit DROP INDEX keeps the intent clear.
DROP INDEX IF EXISTS idx_identities_source;

ALTER TABLE identities DROP COLUMN IF EXISTS source_id;
