-- 050_credential_policy_user_grant_scopes.down.sql
-- Reverses 050. Tokens an agent holds for a person are capped by allowed_scopes
-- again, as before the split.
SET LOCAL lock_timeout = '5s';

ALTER TABLE credential_policies
    DROP COLUMN IF EXISTS user_grant_scopes;
