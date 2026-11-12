-- 067_identity_audit_feed_backfill.down.sql
-- The numbering is dropped with the columns in 066's down; only the index here.
DROP INDEX IF EXISTS idx_identity_audit_logs_feed;
