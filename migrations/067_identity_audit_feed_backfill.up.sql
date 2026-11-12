-- 067_identity_audit_feed_backfill.up.sql
-- Number the audit rows written before 066. The feed index is built in 068.
--
-- Old rows get txid 0, so they sort before every row a live transaction
-- writes, and seq in created_at order. Rows written by old-binary pods during
-- the rollout already have both from 066's column defaults, so the
-- txid IS NULL guard skips them, and the file is safe to re-run.
--
-- LOCK POSTURE (cf. 046/059). golang-migrate runs each file as one implicit
-- transaction. The UPDATE takes ROW EXCLUSIVE: reads and writes continue.
-- It rewrites every pre-066 row once; run it off-peak on a large audit
-- table. A failed run leaves (67, dirty): recover with `migrate force 66`.
--
-- The index is a separate file so that an operator applying migrations with
-- the migrate CLI can stop here (`migrate goto 67`), build it without
-- blocking writes:
--   CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_identity_audit_logs_feed ON identity_audit_logs (txid, seq);
-- and then let 068 find it in place. The embedded migrator run at startup
-- applies 067 and 068 back to back.
SET LOCAL lock_timeout = '5s';

UPDATE identity_audit_logs l
   SET txid = '0'::xid8,
       seq  = n.seq
  FROM (SELECT id, row_number() OVER (ORDER BY created_at, id) AS seq
          FROM identity_audit_logs
         WHERE txid IS NULL) n
 WHERE l.id = n.id;
