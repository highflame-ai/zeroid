-- 001_init_schema.up.sql
-- Creates credential_policies, identities, and issued_credentials tables

-- Credential policies define governance constraints enforced at token issuance time.
-- Each policy is a reusable template assigned to API keys via credential_policy_id.
CREATE TABLE IF NOT EXISTS credential_policies (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id              VARCHAR(255) NOT NULL,
    project_id              VARCHAR(255) NOT NULL,
    name                    VARCHAR(255) NOT NULL,
    description             TEXT,
    max_ttl_seconds         INTEGER NOT NULL DEFAULT 3600,
    allowed_grant_types     TEXT[] NOT NULL DEFAULT '{client_credentials}',
    allowed_scopes          TEXT[],
    required_trust_level    VARCHAR(50),
    required_attestation    VARCHAR(50),
    max_delegation_depth    INTEGER NOT NULL DEFAULT 0,
    is_active               BOOLEAN NOT NULL DEFAULT TRUE,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (account_id, project_id, name)
);

CREATE INDEX IF NOT EXISTS idx_credential_policies_tenant
    ON credential_policies (account_id, project_id);

-- Identities represent any principal that authenticates with ZeroID:
-- agents, applications, MCP servers, internal services, etc.
-- The identity_type determines how policies target this identity
-- and which fields are relevant.
CREATE TABLE IF NOT EXISTS identities (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id           VARCHAR(255) NOT NULL,
    project_id           VARCHAR(255) NOT NULL,
    external_id          VARCHAR(255) NOT NULL,
    name                 VARCHAR(255) NOT NULL DEFAULT '',
    wimse_uri            TEXT NOT NULL,

    -- Classification
    identity_type        VARCHAR(50) NOT NULL DEFAULT 'agent'
        CHECK (identity_type IN ('agent', 'application', 'mcp_server', 'service')),
    sub_type             VARCHAR(50) NOT NULL DEFAULT '',
    trust_level          VARCHAR(50) NOT NULL DEFAULT 'unverified'
        CHECK (trust_level IN ('first_party', 'verified_third_party', 'unverified')),

    -- Ownership and governance
    owner_user_id        VARCHAR(255) NOT NULL,
    allowed_scopes       TEXT[] NOT NULL DEFAULT '{}',
    public_key_pem       TEXT,

    -- Identity metadata (embedded into JWT claims for downstream services)
    framework            VARCHAR(100),
    version              VARCHAR(50),
    publisher            VARCHAR(255),
    description          TEXT,
    capabilities         JSONB NOT NULL DEFAULT '[]'::jsonb,
    labels               JSONB NOT NULL DEFAULT '{}'::jsonb,
    metadata             JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Lifecycle
    status               VARCHAR(50) NOT NULL DEFAULT 'active'
        CHECK (status IN ('pending', 'active', 'suspended', 'deactivated')),
    created_by           VARCHAR(255) NOT NULL DEFAULT '',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (account_id, project_id, external_id)
);

CREATE INDEX IF NOT EXISTS idx_identities_tenant
    ON identities (account_id, project_id);

CREATE INDEX IF NOT EXISTS idx_identities_external_id
    ON identities (external_id);

CREATE INDEX IF NOT EXISTS idx_identities_owner
    ON identities (owner_user_id);

CREATE INDEX IF NOT EXISTS idx_identities_type
    ON identities (identity_type);

CREATE INDEX IF NOT EXISTS idx_identities_sub_type
    ON identities (sub_type)
    WHERE sub_type != '';

CREATE INDEX IF NOT EXISTS idx_identities_tenant_status
    ON identities (account_id, project_id, status);

CREATE INDEX IF NOT EXISTS idx_identities_labels
    ON identities USING GIN (labels);

CREATE INDEX IF NOT EXISTS idx_identities_metadata
    ON identities USING GIN (metadata);

CREATE TABLE IF NOT EXISTS issued_credentials (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id            UUID REFERENCES identities(id) ON DELETE SET NULL,
    account_id             VARCHAR(255) NOT NULL,
    project_id             VARCHAR(255) NOT NULL,
    jti                    VARCHAR(255) NOT NULL UNIQUE,
    subject                TEXT NOT NULL,
    issued_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at             TIMESTAMPTZ NOT NULL,
    ttl_seconds            INTEGER NOT NULL DEFAULT 3600,
    scopes                 TEXT[] NOT NULL DEFAULT '{}',
    is_revoked             BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at             TIMESTAMPTZ,
    revoke_reason          TEXT,
    grant_type             VARCHAR(50) NOT NULL DEFAULT 'client_credentials',
    delegation_depth       INTEGER NOT NULL DEFAULT 0,
    parent_jti             VARCHAR(255),
    delegated_by_wimse_uri TEXT
);

CREATE INDEX IF NOT EXISTS idx_issued_credentials_identity_id
    ON issued_credentials (identity_id);

CREATE INDEX IF NOT EXISTS idx_issued_credentials_jti
    ON issued_credentials (jti);

CREATE INDEX IF NOT EXISTS idx_issued_credentials_expires_at
    ON issued_credentials (expires_at);

CREATE INDEX IF NOT EXISTS idx_issued_credentials_is_revoked
    ON issued_credentials (is_revoked)
    WHERE is_revoked = FALSE;

CREATE INDEX IF NOT EXISTS idx_issued_credentials_tenant
    ON issued_credentials (account_id, project_id);

CREATE INDEX IF NOT EXISTS idx_issued_credentials_parent_jti
    ON issued_credentials (parent_jti)
    WHERE parent_jti IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_issued_credentials_subject
    ON issued_credentials (subject);

CREATE INDEX IF NOT EXISTS idx_issued_credentials_delegated_by
    ON issued_credentials (delegated_by_wimse_uri)
    WHERE delegated_by_wimse_uri IS NOT NULL;

-- Refresh tokens for OAuth2 clients (authorization_code grant with refresh).
-- Family-based rotation with reuse detection per RFC best practices.
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash  TEXT NOT NULL UNIQUE,
    client_id   TEXT NOT NULL,
    account_id  VARCHAR(255) NOT NULL,
    project_id  VARCHAR(255) DEFAULT '',
    user_id     TEXT NOT NULL,
    identity_id UUID REFERENCES identities(id) ON DELETE SET NULL,
    scopes      TEXT DEFAULT '',
    family_id   UUID NOT NULL,
    state       TEXT NOT NULL DEFAULT 'active',
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family
    ON refresh_tokens (family_id);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_client
    ON refresh_tokens (user_id, client_id);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_identity
    ON refresh_tokens (identity_id)
    WHERE identity_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_active
    ON refresh_tokens (state)
    WHERE state = 'active';
