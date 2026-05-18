-- 024_dpop.up.sql
-- DPoP — Demonstrating Proof of Possession (RFC 9449).
--
-- dpop_jti: proof JTI replay-prevention store.
--   INSERT fails on duplicate primary key → replay detected without a pre-check query.
--   expires_at drives cleanup; rows outside the freshness window are purged by the
--   cleanup worker since a proof that old would fail the iat check before JTI lookup.
--
-- issued_credentials.dpop_key_thumbprint: base64url JWK thumbprint (RFC 7638 SHA-256)
--   of the DPoP key bound to this credential (RFC 9449 §6.1). NULL for Bearer tokens.

CREATE TABLE IF NOT EXISTS dpop_jti (
    jti        VARCHAR(512) PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dpop_jti_expires_at ON dpop_jti (expires_at);

ALTER TABLE issued_credentials
    ADD COLUMN IF NOT EXISTS dpop_key_thumbprint TEXT;
