-- 049_credential_policy_required_principal_type.up.sql
-- A credential policy can require that the chain a token belongs to is rooted
-- in a person (human-rooted delegation, highflame-authn#224).
--
-- NULL means any principal, so every existing policy is unaffected. `user`
-- requires a user subject. `owner` (the subject must be the agent's owner) is
-- accepted by the constraint for the personal-agent profile, which ships later;
-- the service refuses it until then.
--
-- A nullable column with no default: catalog-only, no table rewrite.
SET LOCAL lock_timeout = '5s';

ALTER TABLE credential_policies
    ADD COLUMN IF NOT EXISTS required_principal_type VARCHAR(20)
        CONSTRAINT credential_policies_required_principal_type_check
        CHECK (required_principal_type IN ('user', 'owner'));
