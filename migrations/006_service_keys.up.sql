-- 006_service_keys.up.sql
-- Creates service_keys table for API key validation.
-- API keys (zid_sk_*) are validated by ZeroID as part of the universal auth surface.
-- Keys are SHA-256 hashed — plaintext is shown once at creation, never stored.

CREATE TABLE IF NOT EXISTS service_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    description     TEXT DEFAULT '',
    key_prefix      TEXT NOT NULL,
    key_hash        TEXT NOT NULL UNIQUE,
    key_version     INTEGER NOT NULL DEFAULT 1,
    account_id      VARCHAR(255) NOT NULL,
    project_id      VARCHAR(255) DEFAULT '',
    identity_id     UUID REFERENCES identities(id) ON DELETE CASCADE,
    created_by      VARCHAR(255) NOT NULL,
    scopes          TEXT[] DEFAULT '{}',
    product         TEXT DEFAULT '',
    environment     TEXT NOT NULL DEFAULT 'live',
    expires_at      TIMESTAMPTZ,
    state           TEXT NOT NULL DEFAULT 'active',
    revoked_at      TIMESTAMPTZ,
    revoked_by      TEXT DEFAULT '',
    revoke_reason   TEXT DEFAULT '',
    last_used_at    TIMESTAMPTZ,
    last_used_ip    TEXT DEFAULT '',
    usage_count     BIGINT NOT NULL DEFAULT 0,
    metadata        JSONB DEFAULT '{}',
    ip_allowlist    TEXT[] DEFAULT '{}',
    credential_policy_id UUID REFERENCES credential_policies(id),
    rate_limit_rps  INTEGER DEFAULT 0,
    replaced_by     UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_service_keys_account_project_state
    ON service_keys (account_id, project_id, state);

CREATE INDEX IF NOT EXISTS idx_service_keys_identity
    ON service_keys (identity_id)
    WHERE identity_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_service_keys_active
    ON service_keys (state)
    WHERE state = 'active';

CREATE INDEX IF NOT EXISTS idx_service_keys_prefix
    ON service_keys (key_prefix);
