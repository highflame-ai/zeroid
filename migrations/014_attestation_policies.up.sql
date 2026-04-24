-- 014_attestation_policies.up.sql
-- Per-tenant attestation trust configuration.
--
-- Each row declares "for this tenant + this proof type, here are the trusted
-- issuers / allowed hashes / accepted roots". The authoritative check runs
-- in internal/attestation: no row → verifier for that proof type is
-- unconfigured → all verification attempts fail closed.
--
-- The config column is JSONB because each proof type has a different shape
-- (see domain.OIDCPolicyConfig, etc.). Storing inline avoids a table per
-- verifier and lets new verifiers land without schema changes.

CREATE TABLE IF NOT EXISTS attestation_policies (
    id         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id VARCHAR(255) NOT NULL,
    project_id VARCHAR(255) NOT NULL,
    proof_type VARCHAR(50)  NOT NULL,
    config     JSONB        NOT NULL,
    is_active  BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    -- A tenant has at most one policy per proof type. Updating an existing
    -- issuer allowlist is an UPDATE, not a new row — keeps lookups O(1).
    CONSTRAINT uq_attestation_policy_tenant_type
        UNIQUE (account_id, project_id, proof_type)
);

CREATE INDEX IF NOT EXISTS idx_attestation_policies_lookup
    ON attestation_policies (account_id, project_id, proof_type)
    WHERE is_active = TRUE;
