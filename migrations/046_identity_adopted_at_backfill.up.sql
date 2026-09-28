-- 046_identity_adopted_at_backfill.up.sql
-- Backfill identities.adopted_at (045) from the audit trail. Migration 012's
-- trigger logs old/new row JSON on every UPDATE of identities.
--
-- An identity's adoption time is its most recent discovered → pending|active
-- transition, counted only if no revert (a return to discovered) came after
-- it. That mirrors the runtime: a revert clears adopted_at, so a row adopted,
-- reverted, then dismissed (now deactivated) must stay NULL; a row re-adopted
-- after a revert takes the later adoption. Rows with no usable audit history
-- (pre-012, or an audit insert the trigger swallowed) stay NULL and fall back
-- to created_at — today's behaviour, never worse.
--
-- Lock posture: no DDL here, so this takes ROW EXCLUSIVE on identities (reads
-- and writes continue) plus row locks on the adopted rows only. The expensive
-- part is scanning identity_audit_logs, which grows with every connector sync;
-- it runs first, into a temp table, so no identities row is locked while it
-- scans. The write set is small (adopted identities only), so no batching.
-- Heavy audit tables: run off-peak for the I/O, but it does not block.
--
-- Idempotent (adopted_at IS NULL guard), so it is safe to re-run by hand after
-- the rollout completes, to stamp adoptions made on old-binary pods during it.
--
-- modified_by names this migration, so the audit row the trigger writes for
-- each backfilled identity is attributed to it rather than to whoever last
-- touched the row (SystemCallerPrefix convention).

CREATE TEMP TABLE adopt_046 ON COMMIT DROP AS
SELECT identity_id,
       MAX(created_at) FILTER (WHERE old_data ->> 'status' = 'discovered'
                                 AND new_data ->> 'status' IN ('pending', 'active')) AS adopted_at,
       MAX(created_at) FILTER (WHERE new_data ->> 'status' = 'discovered')          AS reverted_at
  FROM identity_audit_logs
 WHERE table_name = 'identities'
   AND action = 'UPDATE'
   AND old_data ->> 'status' IS DISTINCT FROM new_data ->> 'status'
   AND 'discovered' IN (old_data ->> 'status', new_data ->> 'status')
 GROUP BY identity_id;

UPDATE identities i
   SET adopted_at  = a.adopted_at,
       modified_by = 'system:migration_046_adopted_at_backfill'
  FROM adopt_046 a
 WHERE i.id::text = a.identity_id
   AND a.adopted_at IS NOT NULL
   AND (a.reverted_at IS NULL OR a.adopted_at > a.reverted_at)
   AND i.adopted_at IS NULL
   AND i.status <> 'discovered'
   AND i.origin <> 'native';
