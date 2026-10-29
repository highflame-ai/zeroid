-- Drop refresh_tokens.gateway_id where it still exists.
--
-- 001_init_schema once created this column; the migration was later edited to
-- remove it, so databases created before that edit kept it (schema drift).
-- Nothing reads or writes it. IF EXISTS makes this a no-op elsewhere.
--
-- lock_timeout fails fast rather than queueing behind a rotation's row lock.
-- A timeout leaves (63, dirty): recover with `migrate force 62` and re-run.
SET LOCAL lock_timeout = '5s';

ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS gateway_id;
