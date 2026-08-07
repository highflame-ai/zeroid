-- 039_refresh_token_audience.up.sql
-- Persist the audience-profile a refresh token was issued for, so rotation can
-- re-stamp the `aud` claim on every successor access token.
--
-- The external-principal exchange (used by the trusted `user_session` grant)
-- can now issue a rotating refresh token for a PROFILED audience (e.g.
-- "codeoid") so an embedded harness UI keeps its session alive on its own,
-- without the broker (Forge/Studio) re-minting on a timer. When that refresh
-- token is later rotated at /oauth2/token, the refreshed access token MUST
-- carry the same `aud` (and therefore the same server-defined scope profile)
-- as the original — otherwise codeoid's daemon, which validates `aud=codeoid`
-- on every WebSocket message, would reject the refreshed token and drop the
-- session. The built-in refresh path does not carry audience, so we persist it
-- here and read it back in refreshToken().
--
-- Empty string ⇒ a normal (non-audience) refresh token — the authorization_code
-- flow and every existing family — whose rotation is unchanged. Copied verbatim
-- onto every successor row on rotation (like mission_id / dpop_key_thumbprint).
--
-- No index: read only alongside the row it lives on (claimed by token_hash,
-- rotated within its family), never filtered on.
--
-- Lock posture: metadata-only ADD COLUMN on PG 11+ (nullable, no default).

SET LOCAL lock_timeout = '3s';

ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS audience VARCHAR(255);
