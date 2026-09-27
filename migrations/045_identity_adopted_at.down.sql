-- Reverting 045. Roll the binary back FIRST: bun enumerates model columns
-- explicitly, so a binary that knows `adopted_at` fails every identities
-- SELECT/INSERT/UPDATE against a schema without it (SQLSTATE 42703).
--
-- Nothing is lost that can't be rebuilt: the up migration's backfill re-derives
-- adopted_at from identity_audit_logs, so re-applying 045 later restores it
-- (adoptions made while reverted included, since the audit trigger keeps
-- logging them).
SET LOCAL lock_timeout = '3s';

ALTER TABLE identities DROP COLUMN IF EXISTS adopted_at;
