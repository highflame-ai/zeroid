-- Two-clock retention for issued_credentials (issue: delegation graph
-- blanks after token expiry).
--
-- expires_at is the OPERATIONAL clock: how long the token authenticates.
-- audit_retention_until is the EVIDENCE clock: how long the credential row
-- remains queryable so the delegation graph (parent_jti walks, mission_id
-- aggregates) can answer historical questions — "every write by this agent
-- in Q3, with the human approver" — long after the token itself is dead.
--
-- Same model as signing_credentials (023): a merely-expired credential
-- still appears in the graph within the retention window; the cleanup
-- worker prunes on audit_retention_until, not expires_at.
--
-- Nullable by design: rows written by pre-037 code carry NULL and are
-- pruned under the legacy expires_at rule until they age out. The backfill
-- below stamps existing rows so history written before this migration
-- survives too.
--
-- FIXED 400-DAY BACKFILL vs configured window: a migration can't read config,
-- so this hardcodes 400 days (= domain.DefaultAuditRetentionDays). The RUNTIME
-- stamp uses token.audit_retention_days. A deployment running a non-default
-- window (e.g. 30d for data-minimization, or 800d) gets a split: historical
-- rows carry 400d regardless. If that matters, operators must re-stamp
-- out-of-band, e.g.:
--   UPDATE issued_credentials
--   SET audit_retention_until = expires_at + (<days> * INTERVAL '1 day')
--   WHERE issued_at < '<migration-deploy-time>';
-- (Tracked in the release note for this change.)
--
-- LOCK POSTURE (cf. migrations 017/033): golang-migrate runs this whole file
-- in one transaction, so the full-table backfill UPDATE and the
-- non-CONCURRENT CREATE INDEX both hold write-blocking locks on
-- issued_credentials — the per-token high-churn table — for their combined
-- duration, blocking token issuance. This is acceptable at the current fleet
-- size (the pre-037 cleanup bounds the table to ~MaxTTL of rows) but if this
-- ever runs against a large installation, split the backfill into batches and
-- move the index to CREATE INDEX CONCURRENTLY in its own out-of-transaction
-- migration (033's pattern). lock_timeout below fails fast rather than
-- queueing the auth plane behind a long-running query.
SET LOCAL lock_timeout = '5s';

ALTER TABLE issued_credentials
    ADD COLUMN IF NOT EXISTS audit_retention_until TIMESTAMPTZ;

UPDATE issued_credentials
SET audit_retention_until = expires_at + INTERVAL '400 days'
WHERE audit_retention_until IS NULL;

-- Retention pruning (delete only past the retention window).
CREATE INDEX IF NOT EXISTS idx_issued_credentials_retention
    ON issued_credentials (audit_retention_until);
