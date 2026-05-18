-- Workload-attested ephemeral signing credentials.
--
-- A workload generates an ephemeral Ed25519 keypair in
-- memory and attests the PUBLIC half here. ZeroID owns the kid namespace,
-- publishes the verification JWKS, and revokes via CAE. The private key
-- is never sent or stored.
--
-- Two clocks, deliberately decoupled:
--   not_after            — operational: how long the key may SIGN.
--   audit_retention_until — evidence: how long the PUBLIC key remains
--                           resolvable for verifying historical
--                           attestations (>> not_after).
-- A merely-expired (rotated / pod-gone) key still verifies within the
-- retention window; only a REVOKED key fails. This is the correctness
-- property a not_after-only filter cannot express.

CREATE TABLE IF NOT EXISTS signing_credentials (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id            VARCHAR(255) NOT NULL DEFAULT '',
    project_id            VARCHAR(255) NOT NULL DEFAULT '',
    kid                   VARCHAR(255) NOT NULL,
    workload              VARCHAR(255) NOT NULL,  -- trusted-service identity (deployer-defined)
    purpose               VARCHAR(64)  NOT NULL,  -- deployer-configured signing purpose
    algorithm             VARCHAR(32)  NOT NULL,  -- EdDSA
    public_key            TEXT         NOT NULL,  -- base64 raw-url Ed25519 public key (32 bytes)
    not_after             TIMESTAMPTZ  NOT NULL,  -- operational signing expiry
    audit_retention_until TIMESTAMPTZ  NOT NULL,  -- public key resolvable for verification until here
    revoked               BOOLEAN      NOT NULL DEFAULT FALSE,
    revoked_reason        TEXT         NOT NULL DEFAULT '',
    revoked_at            TIMESTAMPTZ,
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (kid)
);

-- Verification lookup: a kid resolves to its key while non-revoked AND
-- inside the audit-retention window (independent of not_after).
CREATE INDEX IF NOT EXISTS idx_signing_credentials_verify
    ON signing_credentials (kid, revoked, audit_retention_until);

-- CAE revocation sweep + operational lookups for a workload, tenant-
-- scoped: every admin read/revoke is bounded by (account_id, project_id)
-- derived from the validated tenant context.
CREATE INDEX IF NOT EXISTS idx_signing_credentials_workload
    ON signing_credentials (account_id, project_id, workload, purpose, created_at);

-- Retention pruning (delete only past the retention window).
CREATE INDEX IF NOT EXISTS idx_signing_credentials_retention
    ON signing_credentials (audit_retention_until) WHERE revoked = FALSE;
