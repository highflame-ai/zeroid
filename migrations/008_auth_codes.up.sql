-- 008_auth_codes.up.sql
-- Tracks consumed authorization codes to enforce single-use per RFC 6749 §4.1.2.
-- Auth codes are stateless HS256 JWTs; this table records consumption so replays
-- are rejected. The credential_jti and refresh_family_id columns enable token
-- revocation when a replay is detected (RFC 6749: "SHOULD revoke all tokens
-- previously issued based on that authorization code").

CREATE TABLE IF NOT EXISTS auth_codes (
    jti               VARCHAR(255) PRIMARY KEY,
    client_id         VARCHAR(255) NOT NULL,
    account_id        VARCHAR(255) NOT NULL,
    project_id        VARCHAR(255) NOT NULL DEFAULT '',
    credential_jti    VARCHAR(255),
    refresh_family_id UUID,
    consumed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at        TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_codes_expires_at
    ON auth_codes (expires_at);
