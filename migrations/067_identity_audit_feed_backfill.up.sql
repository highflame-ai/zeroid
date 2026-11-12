-- 067_identity_audit_feed_backfill.up.sql
-- Number the audit rows written before 066, and index the feed order.
--
-- Old rows get txid 0, so they sort before every row a live transaction
-- writes, and seq in created_at order. Rows written by old-binary pods during
-- the rollout already have both from 066's column defaults, so the
-- txid IS NULL guard skips them, and the file is safe to re-run.
--
-- LOCK POSTURE (cf. 046/059). The UPDATE takes ROW EXCLUSIVE: reads and
-- writes continue. It rewrites every pre-066 row once; run it off-peak on a
-- large audit table. The index build is non-CONCURRENT inside
-- golang-migrate's transaction, so audit inserts (and so the identity writes
-- that trigger them) wait for one scan of the table. Large installations can
-- pre-build it out of band, after the UPDATE, with
--   CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_identity_audit_logs_feed ON identity_audit_logs (txid, seq);
-- and that statement here becomes a no-op.
SET LOCAL lock_timeout = '5s';

UPDATE identity_audit_logs l
   SET txid = '0'::xid8,
       seq  = n.seq
  FROM (SELECT id, row_number() OVER (ORDER BY created_at, id) AS seq
          FROM identity_audit_logs
         WHERE txid IS NULL) n
 WHERE l.id = n.id;

CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_audit_logs_feed
    ON identity_audit_logs (txid, seq);
