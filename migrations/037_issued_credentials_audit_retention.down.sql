-- Ordering: roll BACK the code before running this down migration — post-037
-- code stamps AuditRetentionUntil on every issuance, selects it via the bun
-- model, and names it in the cleanup DELETE; dropping the column under new
-- code breaks issuance, graph reads, and cleanup.
--
-- Data note: per-row retention stamps are lost on down. A later down→up
-- cycle re-derives them as expires_at + 400 days, which may differ from
-- stamps written under a non-default token.audit_retention_days.

DROP INDEX IF EXISTS idx_issued_credentials_retention;

ALTER TABLE issued_credentials
    DROP COLUMN IF EXISTS audit_retention_until;
