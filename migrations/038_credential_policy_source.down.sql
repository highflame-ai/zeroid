-- Revert 038.
-- NOTE: restoring the global name-unique constraint fails if any derived
-- (source IS NOT NULL) policies share a name — expected only in a dev rollback;
-- remove those rows first if needed.

DROP INDEX IF EXISTS uq_credential_policies_source_key;
DROP INDEX IF EXISTS uq_credential_policies_user_name;

ALTER TABLE credential_policies
    ADD CONSTRAINT credential_policies_account_id_project_id_name_key
    UNIQUE (account_id, project_id, name);

ALTER TABLE credential_policies
    DROP COLUMN IF EXISTS source_key,
    DROP COLUMN IF EXISTS source;
