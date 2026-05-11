-- 016_identity_risk_metadata.down.sql
-- Reverses 016_identity_risk_metadata.up.sql by dropping the constraints
-- and columns. Drop constraints first so the column DROP doesn't trip on
-- a constraint that no longer applies.

ALTER TABLE identities
    DROP CONSTRAINT IF EXISTS identities_capability_tier_check,
    DROP CONSTRAINT IF EXISTS identities_risk_tier_check,
    DROP CONSTRAINT IF EXISTS identities_ial_check;

ALTER TABLE identities
    DROP COLUMN IF EXISTS capability_tier,
    DROP COLUMN IF EXISTS risk_tier,
    DROP COLUMN IF EXISTS ial;
