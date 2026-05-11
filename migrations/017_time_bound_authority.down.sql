-- 017_time_bound_authority.down.sql
--
-- IRREVERSIBLE FOR DATA: any expires_at values written on identities or
-- credential_policies while this migration was applied are dropped when
-- the columns are removed. The schema-side rollback is clean, but the
-- time-bound authority configured during the window is lost.

DROP INDEX IF EXISTS idx_service_keys_expiring;
DROP INDEX IF EXISTS idx_credential_policies_expiring;
DROP INDEX IF EXISTS idx_identities_expiring;

ALTER TABLE credential_policies DROP COLUMN IF EXISTS expires_at;
ALTER TABLE identities          DROP COLUMN IF EXISTS expires_at;
-- service_keys.expires_at predates this migration; not dropped.
