-- 034_id_jag_jti.down.sql
-- Drops the ID-JAG single-use replay-prevention store (ADR 0010 D2a).
--
-- DESTROYS REPLAY STATE: after this down runs, every ID-JAG `jti` redeemed
-- before the rollback is forgotten, so a captured-but-already-redeemed ID-JAG
-- that is still within its exp window could be replayed once. Treat as
-- emergency-only.

SET LOCAL lock_timeout = '3s';

DROP INDEX IF EXISTS idx_id_jag_jti_expires_at;
DROP TABLE IF EXISTS id_jag_jti;
