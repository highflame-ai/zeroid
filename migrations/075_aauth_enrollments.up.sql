-- 075_aauth_enrollments.up.sql
-- AAuth Agent Provider (internal/aauth): enrolled agent keys that may
-- refresh their agent token at POST /ap/refresh without a fresh platform
-- token (the bootstrap draft's two-key refresh). Written at /ap/token only
-- when the identity's policy lists aauth_refresh.
--
-- A refresh re-checks everything the platform token proved, except the
-- token itself: the issuer row and the binding (issuer_id, subject) still map
-- to identity_id, the enrollment's first agent token (root_jti) is not
-- revoked, and the enrollment is younger than expires_at. Refreshed tokens
-- are children of root_jti, so revoking it revokes them all.
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
