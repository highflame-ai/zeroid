ALTER TABLE issued_credentials DROP COLUMN IF EXISTS dpop_key_thumbprint;

DROP INDEX IF EXISTS idx_dpop_jti_expires_at;
DROP TABLE IF EXISTS dpop_jti;
