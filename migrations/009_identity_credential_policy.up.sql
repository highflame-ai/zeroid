-- 008_identity_credential_policy.up.sql
-- Makes the credential policy the authoritative source for scopes, TTL,
-- grant types, delegation depth, trust level, and attestation — not the
-- raw allowed_scopes array on the identity row.
--
-- Design: every identity gets a credential_policy_id pointing at the
-- policy that defines its governance ceiling (the "identity policy").
-- API keys still carry their own optional credential_policy_id for
-- per-credential restriction, and the effective authority at token
-- issuance is the intersection of both (AWS/GCP/Azure pattern).
--
-- This migration is written to be safe to re-run and to preserve any
-- existing identity configuration. allowed_scopes is kept for one
-- deprecation cycle so dual-read code paths can fall back to it.

-- Step 1: Add the nullable FK column. NULL is only a transient state
-- during rollout; after backfill every identity points at a policy.
ALTER TABLE identities
    ADD COLUMN IF NOT EXISTS credential_policy_id UUID
    REFERENCES credential_policies(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_identities_credential_policy_id
    ON identities (credential_policy_id)
    WHERE credential_policy_id IS NOT NULL;

-- Step 2: Pre-create a default policy for every tenant that has
-- identities but no default policy yet. Mirrors
-- CredentialPolicyService.EnsureDefaultPolicy so runtime behaviour is
-- unchanged for freshly-provisioned tenants.
INSERT INTO credential_policies (
    account_id,
    project_id,
    name,
    description,
    max_ttl_seconds,
    allowed_grant_types,
    max_delegation_depth,
    is_active
)
SELECT DISTINCT
    i.account_id,
    i.project_id,
    'default',
    'System default credential policy — applied to agents when no explicit policy is specified',
    3600,
    -- Must mirror domain.DefaultAllowedGrantTypes() — covers every NHI
    -- grant so out-of-the-box identities can exercise the full OAuth
    -- surface without authoring a custom policy first. Tenants that
    -- want to disallow delegation or API keys must attach a narrower
    -- policy explicitly.
    ARRAY['client_credentials', 'api_key', 'jwt_bearer', 'token_exchange'],
    -- Must mirror domain.DefaultMaxDelegationDepth. Set generously so
    -- default multi-hop chains succeed without policy authoring.
    5,
    TRUE
FROM identities i
WHERE NOT EXISTS (
    SELECT 1
    FROM credential_policies cp
    WHERE cp.account_id = i.account_id
      AND cp.project_id = i.project_id
      AND cp.name       = 'default'
)
ON CONFLICT (account_id, project_id, name) DO NOTHING;

-- Step 3: Backfill identity → default policy for the tenant. After this
-- runs, every identity row has a non-NULL credential_policy_id.
UPDATE identities
SET credential_policy_id = cp.id
FROM credential_policies cp
WHERE identities.credential_policy_id IS NULL
  AND cp.account_id = identities.account_id
  AND cp.project_id = identities.project_id
  AND cp.name       = 'default';
