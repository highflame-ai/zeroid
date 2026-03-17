-- 001_init_schema.down.sql
-- Reverses 001_init_schema.up.sql
-- Drop tables in reverse dependency order (refresh_tokens and issued_credentials reference identities)

DROP INDEX IF EXISTS idx_refresh_tokens_active;
DROP INDEX IF EXISTS idx_refresh_tokens_identity;
DROP INDEX IF EXISTS idx_refresh_tokens_user_client;
DROP INDEX IF EXISTS idx_refresh_tokens_family;
DROP TABLE IF EXISTS refresh_tokens;

DROP INDEX IF EXISTS idx_issued_credentials_delegated_by;
DROP INDEX IF EXISTS idx_issued_credentials_subject;
DROP INDEX IF EXISTS idx_issued_credentials_parent_jti;
DROP INDEX IF EXISTS idx_issued_credentials_tenant;
DROP INDEX IF EXISTS idx_issued_credentials_is_revoked;
DROP INDEX IF EXISTS idx_issued_credentials_expires_at;
DROP INDEX IF EXISTS idx_issued_credentials_jti;
DROP INDEX IF EXISTS idx_issued_credentials_identity_id;
DROP TABLE IF EXISTS issued_credentials;

DROP INDEX IF EXISTS idx_identities_metadata;
DROP INDEX IF EXISTS idx_identities_labels;
DROP INDEX IF EXISTS idx_identities_tenant_status;
DROP INDEX IF EXISTS idx_identities_sub_type;
DROP INDEX IF EXISTS idx_identities_type;
DROP INDEX IF EXISTS idx_identities_owner;
DROP INDEX IF EXISTS idx_identities_external_id;
DROP INDEX IF EXISTS idx_identities_tenant;
DROP TABLE IF EXISTS identities;

DROP INDEX IF EXISTS idx_credential_policies_tenant;
DROP TABLE IF EXISTS credential_policies;
