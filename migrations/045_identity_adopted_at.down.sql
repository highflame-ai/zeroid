-- Reverting 045. Roll the binary back FIRST: bun enumerates model columns
-- explicitly, so a binary that knows `adopted_at` fails every identities
-- SELECT/INSERT/UPDATE against a schema without it (SQLSTATE 42703).
--
-- Re-applying 045 + 046 later rebuilds adopted_at from identity_audit_logs,
-- including adoptions made while reverted (the trigger keeps logging them).
-- Rows whose audit insert failed fall back to created_at ordering.
SET LOCAL lock_timeout = '3s';

ALTER TABLE identities DROP COLUMN IF EXISTS adopted_at;
