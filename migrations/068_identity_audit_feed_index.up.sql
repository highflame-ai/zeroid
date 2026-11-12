-- 068_identity_audit_feed_index.up.sql
-- Index the feed order (txid, seq). Every row has both by now: new rows from
-- 066's column defaults, older rows from 067's backfill.
--
-- LOCK POSTURE (cf. 017/055/059). Non-CONCURRENT inside golang-migrate's
-- implicit transaction, so audit inserts (and so the identity, credential
-- policy, service key and external issuer writes whose triggers make them)
-- wait for one scan of the table. Large installations can build it out of
-- band after 067, with
--   CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_identity_audit_logs_feed ON identity_audit_logs (txid, seq);
-- and this migration becomes a no-op. A failed run leaves (68, dirty):
-- recover with `migrate force 67`.
SET LOCAL lock_timeout = '5s';

CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_audit_logs_feed
    ON identity_audit_logs (txid, seq);
