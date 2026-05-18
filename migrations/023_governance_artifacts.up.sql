-- 023_governance_artifacts.up.sql
-- Adds Decision-Rights Matrix (DRM) and Constraint Catalog version tables
-- per issue #59. Both artifacts are append-only governance records whose
-- SHA-256 hashes are bound into delegation tokens at issuance time so that
-- post-hoc audit can answer "which governance version authorized this token?".
--
-- DRM rows enumerate permitted delegation patterns and are user-authored
-- via the admin API. Constraint Catalog rows are signed snapshots of the
-- active policy set, re-signed every 24h by an internal worker; multiple
-- catalog rows can share the same Hash (re-sign of unchanged content)
-- but each carries a distinct SignedAt to prove liveness.

CREATE TABLE IF NOT EXISTS decision_rights_matrix (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id      VARCHAR(255) NOT NULL,
    project_id      VARCHAR(255) NOT NULL,
    version         VARCHAR(64)  NOT NULL,
    effective_at    TIMESTAMPTZ  NOT NULL,
    expires_at      TIMESTAMPTZ,
    document        JSONB        NOT NULL,
    hash            VARCHAR(80)  NOT NULL,  -- "sha256:<hex>"
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (account_id, project_id, version)
);

CREATE INDEX IF NOT EXISTS idx_drm_tenant_effective
    ON decision_rights_matrix (account_id, project_id, effective_at DESC);

-- Append-only enforcement: refuse UPDATE/DELETE on DRM rows. The issue
-- requires "immutable writes" for governance artifacts so post-hoc audit
-- can rely on the row history being intact.
CREATE OR REPLACE FUNCTION drm_block_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'decision_rights_matrix is append-only — % blocked', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS drm_block_update ON decision_rights_matrix;
CREATE TRIGGER drm_block_update
    BEFORE UPDATE ON decision_rights_matrix
    FOR EACH ROW EXECUTE FUNCTION drm_block_mutation();

DROP TRIGGER IF EXISTS drm_block_delete ON decision_rights_matrix;
CREATE TRIGGER drm_block_delete
    BEFORE DELETE ON decision_rights_matrix
    FOR EACH ROW EXECUTE FUNCTION drm_block_mutation();


CREATE TABLE IF NOT EXISTS constraint_catalog_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id      VARCHAR(255) NOT NULL,
    project_id      VARCHAR(255) NOT NULL,
    version         VARCHAR(64)  NOT NULL,         -- ISO 8601 effective-at by convention
    effective_at    TIMESTAMPTZ  NOT NULL,
    document        JSONB        NOT NULL,         -- opaque blob — ZeroID hashes/signs but does not parse
    hash            VARCHAR(80)  NOT NULL,         -- "sha256:<hex>" of canonical document bytes
    signed_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    signature       TEXT         NOT NULL,         -- ES256 signature over hash||signed_at
    signing_key_id  VARCHAR(255) NOT NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_catalog_tenant_signed
    ON constraint_catalog_versions (account_id, project_id, signed_at DESC);

CREATE INDEX IF NOT EXISTS idx_catalog_tenant_effective
    ON constraint_catalog_versions (account_id, project_id, effective_at DESC);

-- Bind governance hashes into the credential record at issuance time so the
-- policy_drift signal emitter can identify outstanding tokens issued under
-- a now-superseded DRM or catalog version without having to decode every JWT.
ALTER TABLE issued_credentials
    ADD COLUMN IF NOT EXISTS drm_hash               VARCHAR(80),
    ADD COLUMN IF NOT EXISTS constraint_catalog_hash VARCHAR(80);

CREATE INDEX IF NOT EXISTS idx_issued_credentials_drm_hash
    ON issued_credentials (account_id, project_id, drm_hash)
    WHERE drm_hash IS NOT NULL AND is_revoked = FALSE;

CREATE INDEX IF NOT EXISTS idx_issued_credentials_catalog_hash
    ON issued_credentials (account_id, project_id, constraint_catalog_hash)
    WHERE constraint_catalog_hash IS NOT NULL AND is_revoked = FALSE;
