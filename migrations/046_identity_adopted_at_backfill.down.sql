-- No-op: the backfilled values are removed with the column by 045's down
-- migration (DROP COLUMN). 046's up is idempotent (adopted_at IS NULL guard),
-- so re-applying it after a revert is safe.
SELECT 1;
