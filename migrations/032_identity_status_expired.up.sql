-- Add 'expired' to the identity status CHECK constraint.
-- Subagent identities transition to 'expired' on session stop.
ALTER TABLE identities
    DROP CONSTRAINT identities_status_check,
    ADD CONSTRAINT identities_status_check
        CHECK (status IN ('pending', 'active', 'suspended', 'deactivated', 'expired'));
