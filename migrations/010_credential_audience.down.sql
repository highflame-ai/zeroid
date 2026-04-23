-- 010_credential_audience.down.sql
ALTER TABLE issued_credentials DROP COLUMN IF EXISTS audience;
