-- 073_aauth.up.sql
-- AAuth Agent Provider (internal/aauth). Everything AAuth stores, in one
-- migration: AAuth arrives with this change, so nothing deployed needs to be
-- moved forward step by step.

-- Which agent key redeemed each workload assertion at POST /ap/token.
--
-- The assertion itself is spent in the shared single-use store (dpop_jti,
-- under the federated client assertion's key), so a platform token redeemed
-- at the token endpoint can't be redeemed here and the reverse. This table
-- adds what that store can't say: the key the first redemption bound. The
-- same key may redeem the same assertion again until it expires, once it
-- minted, because a Kubernetes projected token can't be re-minted on demand
-- and every worker and restarted container of a pod shares it. Any other key
-- is refused.
CREATE TABLE IF NOT EXISTS aauth_bootstrap_redemptions (
    replay_key  VARCHAR(512) PRIMARY KEY,
    jkt         VARCHAR(64)  NOT NULL,
    minted      BOOLEAN      NOT NULL DEFAULT FALSE,
    -- refused: the first redemption was refused (no binding, not opted in,
    -- spent elsewhere). Its key is then refused at once, never told to retry.
    refused     BOOLEAN      NOT NULL DEFAULT FALSE,
    expires_at  TIMESTAMPTZ  NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_aauth_bootstrap_redemptions_expires_at
    ON aauth_bootstrap_redemptions (expires_at);

-- The person server of the agents a policy governs: the ps claim of their
-- agent tokens. NULL for agents with no person server.
ALTER TABLE credential_policies ADD COLUMN IF NOT EXISTS aauth_person_server TEXT;

-- One row per agent or sub-agent token issued with a ps claim. Once ZeroID
-- treats the token as inactive (its credential revoked, its identity no
-- longer active, or an identity above it in the registration tree stopped),
-- a worker revokes it at the person server, the only recipient of an agent
-- token revocation (protocol draft, "Who Revokes What"), until it succeeds,
-- the person server says it takes none, or the token expires.
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
    -- A live token's identity chain is re-checked at most every
    -- next_check_at interval; chain_stopped records a stopped one.
    next_check_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    chain_stopped   BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_aauth_ps_revocations_pending
    ON aauth_ps_revocations (next_attempt_at) WHERE notified_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_aauth_ps_revocations_check
    ON aauth_ps_revocations (next_check_at) WHERE notified_at IS NULL AND NOT chain_stopped;
CREATE INDEX IF NOT EXISTS idx_aauth_ps_revocations_expires_at
    ON aauth_ps_revocations (expires_at);

-- Enrolled agent keys that may refresh their agent token at POST /ap/refresh
-- without a fresh platform token (the bootstrap draft's two-key refresh).
-- Written at /ap/token only when the identity's policy lists aauth_refresh.
--
-- A refresh re-checks everything the platform token proved, except the
-- token itself: the issuer row and the binding (issuer_id, subject) still map
-- to identity_id, no agent token of the enrollment (root_jti or a refresh,
-- its child) has been revoked, and the enrollment is younger than
-- expires_at. Revoking the agent's current token cuts off the durable key.
CREATE TABLE IF NOT EXISTS aauth_enrollments (
    durable_jkt VARCHAR(64)  PRIMARY KEY,
    identity_id UUID         NOT NULL,
    account_id  VARCHAR(255) NOT NULL,
    project_id  VARCHAR(255) NOT NULL,
    issuer_id   UUID         NOT NULL,
    subject     TEXT         NOT NULL,
    root_jti    VARCHAR(255) NOT NULL,
    enrolled_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ  NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_aauth_enrollments_expires_at ON aauth_enrollments (expires_at);
