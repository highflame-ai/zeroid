-- 057_external_issuer_trust_email.down.sql
SET LOCAL lock_timeout = '3s';

ALTER TABLE external_issuers DROP COLUMN IF EXISTS trust_email;
