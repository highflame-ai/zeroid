-- 044_default_policy_add_ciba_grant.down.sql
-- Remove the CIBA grant from default policies again. Restores the pre-044
-- shape for every default row (including fresh rows that were created with
-- the grant by the Go defaults), which is what a downgrade to a pre-#304
-- binary expects.
UPDATE credential_policies
SET allowed_grant_types = array_remove(allowed_grant_types, 'urn:openid:params:grant-type:ciba'),
    updated_at = NOW()
WHERE name = 'default'
  AND 'urn:openid:params:grant-type:ciba' = ANY(allowed_grant_types);
