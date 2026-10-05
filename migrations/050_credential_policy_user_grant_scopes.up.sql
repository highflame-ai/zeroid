-- 050_credential_policy_user_grant_scopes.up.sql
-- Split scope ceilings (D10 of human-rooted delegation, highflame-authn#240).
--
-- One list, allowed_scopes, capped both an agent's own tokens and every token
-- it held for a person, so an agent registered with [nhi:manage] that asked for
-- crm:write under Alice got an empty intersection. user_grant_scopes caps only
-- what an agent may hold for a person; allowed_scopes keeps capping its own
-- authority. NULL (or empty) means no extra cap: the person's own grant bounds
-- the chain.
--
-- It applies only where the person's grant is itself bounded — a delegated
-- user chain (by its parent), ID-JAG (by the IdP), authorization_code and
-- refresh (by consent). The trusted-broker, ID-token and CIBA roots are bounded
-- only by the caller's request, so they keep allowed_scopes until the ceiling
-- rule enforces on them.
--
-- A nullable column with no default: catalog-only, no table rewrite.
SET LOCAL lock_timeout = '5s';

ALTER TABLE credential_policies
    ADD COLUMN IF NOT EXISTS user_grant_scopes TEXT[];
