-- IRREVERSIBLE FOR LIVE DPoP-BOUND TOKENS: dropping dpop_key_thumbprint
-- erases the cnf.jkt binding metadata for every active DPoP-bound credential.
-- After this down runs, resource servers introspecting those tokens no
-- longer see a cnf claim and will refuse the DPoP-bound presentation.
-- Treat as emergency-only.

SET LOCAL lock_timeout = '3s';

ALTER TABLE issued_credentials DROP COLUMN IF EXISTS dpop_key_thumbprint;

DROP INDEX IF EXISTS idx_dpop_jti_expires_at;
DROP TABLE IF EXISTS dpop_jti;
