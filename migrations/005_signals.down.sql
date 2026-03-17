-- 005_signals.down.sql
-- Reverses 005_signals.up.sql

DROP INDEX IF EXISTS idx_cae_signals_severity;
DROP INDEX IF EXISTS idx_cae_signals_tenant;
DROP INDEX IF EXISTS idx_cae_signals_created_at;
DROP INDEX IF EXISTS idx_cae_signals_signal_type;
DROP INDEX IF EXISTS idx_cae_signals_identity_id;
DROP TABLE IF EXISTS cae_signals;
