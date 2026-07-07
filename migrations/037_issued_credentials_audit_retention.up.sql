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
-- survives too. 400 days mirrors the signing_credentials default
-- (signing_credentials.audit_retention_days).

ALTER TABLE issued_credentials
    ADD COLUMN IF NOT EXISTS audit_retention_until TIMESTAMPTZ;

UPDATE issued_credentials
SET audit_retention_until = expires_at + INTERVAL '400 days'
WHERE audit_retention_until IS NULL;

-- Retention pruning (delete only past the retention window).
CREATE INDEX IF NOT EXISTS idx_issued_credentials_retention
    ON issued_credentials (audit_retention_until);
