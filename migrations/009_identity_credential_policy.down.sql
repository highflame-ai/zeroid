-- 008_identity_credential_policy.down.sql
-- Reverses 008_identity_credential_policy.up.sql.
-- Dropping the FK column is safe: allowed_scopes on identities is still
-- populated, so legacy scope resolution continues to work without the
-- policy link.

DROP INDEX IF EXISTS idx_identities_credential_policy_id;

ALTER TABLE identities
    DROP COLUMN IF EXISTS credential_policy_id;
