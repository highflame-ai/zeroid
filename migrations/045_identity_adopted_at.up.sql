-- 045_identity_adopted_at.up.sql
-- Record WHEN a discovered identity was adopted, so the registry can list
-- adopted agents newest-adoption-first.
--
-- The registry lists by created_at DESC. For a discovered identity created_at is
-- when a connector sync first SAW it, not when a human adopted it, so adopted
-- agents land wherever they were discovered — often months back — and the list
-- reads as random. updated_at is no substitute: reconcileDiscovered bumps it on
-- every sync (it doubles as the prune "last seen" marker), so ordering on it
-- would reshuffle the list after each sync.
--
-- Set by UpdateIdentity on discovered → pending|active, cleared when an
-- adoption is reverted (pending → discovered). NULL for native identities and
-- for anything never adopted; the list orders by COALESCE(adopted_at,
-- created_at), so those keep their creation time.
--
-- Lock posture: nullable, no default → metadata-only ADD COLUMN on PG 11+. The
-- risk is the ACCESS EXCLUSIVE lock queue on a hot table, hence lock_timeout.
SET LOCAL lock_timeout = '3s';

ALTER TABLE identities
    ADD COLUMN IF NOT EXISTS adopted_at TIMESTAMPTZ;

-- Backfill from the audit trail (migration 012 logs old/new row JSON on every
-- UPDATE). An identity's adoption time is its most recent discovered →
-- pending|active transition. Only rows that are adopted NOW are touched, so a
-- row adopted and then reverted stays NULL. Rows with no such audit entry
-- (audit rows pruned, or pre-012 history) stay NULL and fall back to
-- created_at, which is today's behaviour — never worse.
--
-- The trigger records this UPDATE too, so each backfilled row gains one audit
-- entry. That is accurate (the column did change) and bounded by the number of
-- adopted identities, which is small.
UPDATE identities i
   SET adopted_at = a.adopted_at
  FROM (
        SELECT identity_id, MAX(created_at) AS adopted_at
          FROM identity_audit_logs
         WHERE table_name = 'identities'
           AND action = 'UPDATE'
           AND old_data ->> 'status' = 'discovered'
           AND new_data ->> 'status' IN ('pending', 'active')
         GROUP BY identity_id
       ) a
 WHERE i.id::text = a.identity_id
   AND i.adopted_at IS NULL
   AND i.status <> 'discovered'
   AND i.origin <> 'native';
