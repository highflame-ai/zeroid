-- 006_service_keys.down.sql
-- Reverses 006_service_keys.up.sql

DROP INDEX IF EXISTS idx_service_keys_prefix;
DROP INDEX IF EXISTS idx_service_keys_active;
DROP INDEX IF EXISTS idx_service_keys_identity;
DROP INDEX IF EXISTS idx_service_keys_account_project_state;
DROP TABLE IF EXISTS service_keys;
