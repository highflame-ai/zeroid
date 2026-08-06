-- 040_observed_idjag_resources.down.sql
DROP INDEX IF EXISTS idx_observed_idjag_resources_tenant_last_seen;
DROP TABLE IF EXISTS observed_idjag_resources;
