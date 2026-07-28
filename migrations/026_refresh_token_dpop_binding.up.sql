-- 026_refresh_token_dpop_binding.up.sql
-- Refresh-token DPoP binding (RFC 9449 §5).
--
-- A refresh token issued in conjunction with a DPoP-bound access token must
-- itself be bound to the same public key — and every subsequent refresh
-- request must present a proof signed by the same key. Without this, an
-- attacker who steals a refresh token (the persistent half of a long-running
-- session) could redeem it with a different key and unbox an unbound access
-- token, undoing the entire DPoP guarantee for the chain.
--
-- The column is populated from the request-time DPoP proof when the original
-- /oauth2/token call that minted the refresh was DPoP-bound, copied to the
-- successor row on every rotation, and validated against the presented proof
-- inside RotateRefreshToken's transaction. NULL ⇒ unbound (Bearer) — rotation
-- in that case accepts any proof or none.
--
-- Lock posture: metadata-only ADD COLUMN on PG 11+ (nullable, no default).

SET LOCAL lock_timeout = '3s';

ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS dpop_key_thumbprint TEXT;
