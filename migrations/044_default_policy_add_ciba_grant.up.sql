-- 044_default_policy_add_ciba_grant.up.sql
-- Migration 009 backfilled each tenant's `default` credential policy with an
-- allowed_grant_types list that "must mirror domain.DefaultAllowedGrantTypes()".
-- PR #304 then added the CIBA grant (urn:openid:params:grant-type:ciba) to
-- those Go defaults so bound OAuth clients can redeem a human-approved
-- backchannel request under the default policy — but stored default rows never
-- self-heal (CredentialPolicyService.EnsureDefaultPolicy returns the existing
-- row untouched), so every deployment that upgraded across #304 kept a default
-- policy without the grant and saw bound-client CIBA redemption refused with
-- access_denied. Only fresh databases got the new default.
--
-- Append the grant to every default policy that lacks it. Scoped to
-- name = 'default' (domain.DefaultPolicyName): tenant-authored policies are
-- deliberate allow-lists and are left alone. Idempotent — re-running is a
-- no-op once the grant is present.
UPDATE credential_policies
SET allowed_grant_types = array_append(allowed_grant_types, 'urn:openid:params:grant-type:ciba'),
    updated_at = NOW()
WHERE name = 'default'
  AND NOT ('urn:openid:params:grant-type:ciba' = ANY(allowed_grant_types));
