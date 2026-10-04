-- 047_delegation_profile.down.sql
-- Reverses 047. Dropping the principal columns discards the principal of
-- every credential minted since 047, so per-user revocation (phase 2) cannot
-- reach those chains afterwards; owner revocation is unaffected. Dropping
-- tenant_settings returns every tenant to the legacy profile.
SET LOCAL lock_timeout = '5s';

DROP TABLE IF EXISTS tenant_settings;

ALTER TABLE refresh_tokens
    DROP COLUMN IF EXISTS principal_iss;

ALTER TABLE issued_credentials
    DROP COLUMN IF EXISTS principal_iss,
    DROP COLUMN IF EXISTS principal_sub,
    DROP COLUMN IF EXISTS principal_type;
