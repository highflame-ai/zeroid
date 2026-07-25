-- Dropping audience removes the `aud` linkage from every active refresh-token
-- family. After down + re-apply, rotating an audience-profile refresh token
-- (e.g. codeoid) would issue a successor access token WITHOUT the `aud` claim,
-- which the harness daemon rejects — bricking those sessions until re-issued.
-- Normal (non-audience) refresh families are unaffected.

SET LOCAL lock_timeout = '3s';

ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS audience;
