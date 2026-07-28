-- Revert: remove 'expired' from the identity status CHECK constraint.
-- Any rows with status='expired' must be updated first.
UPDATE identities SET status = 'deactivated' WHERE status = 'expired';

ALTER TABLE identities
    DROP CONSTRAINT identities_status_check,
    ADD CONSTRAINT identities_status_check
        CHECK (status IN ('pending', 'active', 'suspended', 'deactivated'));
