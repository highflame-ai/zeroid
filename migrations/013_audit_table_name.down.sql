DROP INDEX IF EXISTS idx_identity_audit_logs_table_name;
ALTER TABLE identity_audit_logs DROP COLUMN IF EXISTS table_name;
