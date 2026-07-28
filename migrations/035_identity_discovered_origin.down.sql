-- Revert 035: drop `origin`, remove `discovered` from the status CHECK.
--
-- Discovered rows have no analog in the pre-035 enum, so reconcile them first:
-- promote to `deactivated` (ISO "Archived") so the narrowed CHECK holds. They
-- are credential-less and not usable, so this loses only posture data, never
-- an auth principal.
UPDATE identities SET status = 'deactivated' WHERE status = 'discovered';

DROP INDEX IF EXISTS idx_identities_origin;

-- Dropping the column also drops its inline CHECK (identities_origin_check).
ALTER TABLE identities DROP COLUMN IF EXISTS origin;

ALTER TABLE identities
    DROP CONSTRAINT identities_status_check,
    ADD CONSTRAINT identities_status_check
        CHECK (status IN ('pending', 'active', 'suspended', 'deactivated', 'expired'));
