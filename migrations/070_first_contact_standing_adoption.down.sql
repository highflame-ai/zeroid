-- 070_first_contact_standing_adoption.down.sql
-- Restores 069's rate-limit index and drops the columns that say who last
-- changed a row's first-contact mapping.
SET LOCAL lock_timeout = '3s';

DROP INDEX IF EXISTS external_issuer_bindings_first_contact_written_idx;
CREATE INDEX IF NOT EXISTS external_issuer_bindings_first_contact_idx
    ON external_issuer_bindings (issuer_id, created_at)
    WHERE created_by = 'system:first_contact';

ALTER TABLE external_issuers
    DROP COLUMN IF EXISTS first_contact_updated_at,
    DROP COLUMN IF EXISTS first_contact_updated_by;
