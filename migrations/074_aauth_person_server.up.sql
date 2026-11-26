-- 074_aauth_person_server.up.sql
-- AAuth Agent Provider (internal/aauth): an agent's person server, and the
-- agent tokens ZeroID must revoke there.

-- The person server of the agents a policy governs: the ps claim of their
-- agent tokens. NULL for agents with no person server.
ALTER TABLE credential_policies ADD COLUMN IF NOT EXISTS aauth_person_server TEXT;

-- One row per agent or sub-agent token issued with a ps claim. When the
-- token's credential is revoked (or its identity stops), a worker revokes it
-- at the person server, the only recipient of an agent token revocation
-- (protocol draft, "Who Revokes What"), until it succeeds, the person server
-- says it takes none, or the token expires.
CREATE TABLE IF NOT EXISTS aauth_ps_revocations (
    jti             VARCHAR(255) PRIMARY KEY,
    person_server   TEXT         NOT NULL,
    expires_at      TIMESTAMPTZ  NOT NULL,
    -- notified_at: a terminal outcome was reached (outcome says which).
    notified_at     TIMESTAMPTZ,
    outcome         VARCHAR(32),
    attempts        INTEGER      NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_error      TEXT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_aauth_ps_revocations_pending
    ON aauth_ps_revocations (next_attempt_at) WHERE notified_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_aauth_ps_revocations_expires_at
    ON aauth_ps_revocations (expires_at);
