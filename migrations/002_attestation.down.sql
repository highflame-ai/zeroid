-- 002_attestation.down.sql
-- Reverses 002_attestation.up.sql

DROP INDEX IF EXISTS idx_attestation_records_expiry;
DROP INDEX IF EXISTS idx_attestation_records_is_verified;
DROP INDEX IF EXISTS idx_attestation_records_tenant;
DROP INDEX IF EXISTS idx_attestation_records_identity_id;
DROP TABLE IF EXISTS attestation_records;
