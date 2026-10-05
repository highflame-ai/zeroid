-- 048_credential_policy_jwt_typ.down.sql
-- Reverses 048. rfc8693-profile tenants revert to the default `at+jwt` for
-- every policy, including ones that had chosen `JWT` for JWT-SVID consumers.
SET LOCAL lock_timeout = '5s';

ALTER TABLE credential_policies
    DROP COLUMN IF EXISTS jwt_typ;
