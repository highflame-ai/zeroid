-- IRREVERSIBLE FOR BOUND REFRESH TOKENS: dropping dpop_key_thumbprint erases the
-- binding for every active refresh token issued under DPoP. After down + re-apply,
-- a previously-bound refresh token will rotate as if it had never been bound.
-- Treat as emergency-only.

SET LOCAL lock_timeout = '3s';

ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS dpop_key_thumbprint;
