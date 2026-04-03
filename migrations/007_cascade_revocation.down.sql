-- 007_cascade_revocation.down.sql
-- Reverses 007_cascade_revocation.up.sql

DROP FUNCTION IF EXISTS revoke_credentials_cascade(UUID, TEXT, TEXT, TEXT);
