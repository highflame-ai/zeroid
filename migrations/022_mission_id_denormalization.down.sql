-- 022_mission_id_denormalization.down.sql
-- Reverses 022_mission_id_denormalization.up.sql.

DROP INDEX IF EXISTS idx_cae_signals_mission_id;
ALTER TABLE cae_signals DROP COLUMN IF EXISTS mission_id;

DROP INDEX IF EXISTS idx_issued_credentials_mission_id;
ALTER TABLE issued_credentials DROP COLUMN IF EXISTS mission_id;
