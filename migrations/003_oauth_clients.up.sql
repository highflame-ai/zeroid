-- 003_oauth_clients.up.sql
-- Creates oauth_clients and oauth_tokens tables

CREATE TABLE IF NOT EXISTS oauth_clients (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id                   VARCHAR(255) NOT NULL,
    client_secret               VARCHAR(255) DEFAULT '',
    name                        VARCHAR(255) NOT NULL,
    description                 TEXT DEFAULT '',

    -- Classification (RFC 6749 §2.1, RFC 7591)
    client_type                 VARCHAR(20) NOT NULL DEFAULT 'public',   -- public, confidential
    token_endpoint_auth_method  VARCHAR(50) DEFAULT 'none',              -- none, client_secret_basic, client_secret_post, private_key_jwt

    -- OAuth configuration
    grant_types                 TEXT[] NOT NULL DEFAULT '{"client_credentials"}',
    redirect_uris               TEXT[] NOT NULL DEFAULT '{}',
    scopes                      TEXT[] NOT NULL DEFAULT '{}',

    -- Token lifetime (per-client override, 0 = use server default)
    access_token_ttl            INTEGER DEFAULT 0,
    refresh_token_ttl           INTEGER DEFAULT 0,

    -- Secret management
    client_secret_expires_at    TIMESTAMPTZ,

    -- Key material (for private_key_jwt auth — RFC 7523)
    jwks_uri                    TEXT DEFAULT '',
    jwks                        JSONB,

    -- Software identity (RFC 7591 — identifies the client software)
    software_id                 VARCHAR(255) DEFAULT '',
    software_version            VARCHAR(100) DEFAULT '',

    -- Ownership
    contacts                    TEXT[] DEFAULT '{}',

    -- Extensibility (avoids future schema changes)
    metadata                    JSONB DEFAULT '{}',

    -- Lifecycle
    is_active                   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_clients_client_id
    ON oauth_clients (client_id);

CREATE TABLE IF NOT EXISTS oauth_tokens (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id     VARCHAR(255) NOT NULL,
    account_id    VARCHAR(255) NOT NULL,
    project_id    VARCHAR(255) NOT NULL,
    identity_id   UUID REFERENCES identities(id) ON DELETE SET NULL,
    jti           VARCHAR(255) NOT NULL UNIQUE,
    token_type    VARCHAR(50) NOT NULL DEFAULT 'Bearer',
    scopes        TEXT[] NOT NULL DEFAULT '{}',
    issued_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ NOT NULL,
    is_revoked    BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at    TIMESTAMPTZ,
    grant_type    VARCHAR(50) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_oauth_tokens_jti
    ON oauth_tokens (jti);

CREATE INDEX IF NOT EXISTS idx_oauth_tokens_client_id
    ON oauth_tokens (client_id);

CREATE INDEX IF NOT EXISTS idx_oauth_tokens_expires_at
    ON oauth_tokens (expires_at);

CREATE INDEX IF NOT EXISTS idx_oauth_tokens_tenant
    ON oauth_tokens (account_id, project_id);
