-- 016_identity_risk_metadata.up.sql
-- Adds three optional metadata columns to identities for CoSAI §3.2
-- capability–risk classification + NIST SP 800-63 Identity Assurance Levels.
--
-- All three are nullable. Existing rows default to NULL ("unclassified").
-- CHECK constraints enforce the enum values at the DB layer; the service
-- layer also validates so callers get structured 400s instead of 23514
-- constraint-violation errors.
--
-- Spec:
--   https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/agentic-identity-and-access-control.md

ALTER TABLE identities
    ADD COLUMN IF NOT EXISTS capability_tier VARCHAR(20),
    ADD COLUMN IF NOT EXISTS risk_tier       VARCHAR(20),
    ADD COLUMN IF NOT EXISTS ial             VARCHAR(20);

ALTER TABLE identities
    ADD CONSTRAINT identities_capability_tier_check
        CHECK (capability_tier IS NULL OR capability_tier IN ('low', 'high'));

ALTER TABLE identities
    ADD CONSTRAINT identities_risk_tier_check
        CHECK (risk_tier IS NULL OR risk_tier IN ('low', 'high'));

ALTER TABLE identities
    ADD CONSTRAINT identities_ial_check
        CHECK (ial IS NULL OR ial IN ('ial1', 'ial2', 'ial3'));
