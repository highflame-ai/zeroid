CREATE TABLE IF NOT EXISTS downstream_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id      VARCHAR(255) NOT NULL,
    project_id      VARCHAR(255) NOT NULL,
    user_id         VARCHAR(255) NOT NULL,
    server_slug     VARCHAR(255) NOT NULL,
    access_token    TEXT NOT NULL,
    refresh_token   TEXT DEFAULT '',
    token_type      VARCHAR(50) NOT NULL DEFAULT 'Bearer',
    scopes          TEXT DEFAULT '',
    expires_at      TIMESTAMPTZ,
    oauth_config    JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_downstream_tokens_unique
    ON downstream_tokens (user_id, server_slug, account_id, project_id);

CREATE INDEX IF NOT EXISTS idx_downstream_tokens_lookup
    ON downstream_tokens (account_id, project_id, user_id);
