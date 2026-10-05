-- 049_credential_policy_required_principal_type.down.sql
-- Reverses 049. Policies that required a user subject stop enforcing it.
SET LOCAL lock_timeout = '5s';

ALTER TABLE credential_policies
    DROP COLUMN IF EXISTS required_principal_type;
