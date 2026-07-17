-- 037: source + source_key on credential_policies (auto-derived policy dedup).
--
-- A policy auto-derived at adoption (e.g. the least-privilege scope ceiling admin
-- creates from a discovered agent's IdP-granted scopes, highflame-admin#1257)
-- needs a stable dedup identity that is NOT its human-facing name, so re-deriving
-- the same posture reuses one row while the display name stays readable:
--   source     — provenance, e.g. 'discovery'  (NULL = user-authored policy)
--   source_key — stable identity WITHIN that source (a posture hash)
--
-- The original UNIQUE(account_id, project_id, name) is split into two PARTIAL
-- unique indexes: names stay unique for user policies (source IS NULL); derived
-- policies are keyed by (source, source_key) instead, freeing their name.

ALTER TABLE credential_policies
    ADD COLUMN IF NOT EXISTS source     VARCHAR(50),
    ADD COLUMN IF NOT EXISTS source_key VARCHAR(255);

ALTER TABLE credential_policies
    DROP CONSTRAINT IF EXISTS credential_policies_account_id_project_id_name_key;

CREATE UNIQUE INDEX IF NOT EXISTS uq_credential_policies_user_name
    ON credential_policies (account_id, project_id, name)
    WHERE source IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_credential_policies_source_key
    ON credential_policies (account_id, project_id, source, source_key)
    WHERE source IS NOT NULL;
