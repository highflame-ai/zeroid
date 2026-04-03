-- 008_revoke_credential_cascade.down.sql
-- Reverses 008_revoke_credential_cascade.up.sql

DROP FUNCTION IF EXISTS revoke_credential_cascade(UUID, TEXT, TEXT, TIMESTAMPTZ, TEXT);
