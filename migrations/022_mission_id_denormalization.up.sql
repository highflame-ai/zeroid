-- 022_mission_id_denormalization.up.sql
-- Adds mission_id (a delegation-tree-scoped opaque identifier) as a
-- first-class column on issued_credentials and cae_signals so workflow-
-- spanning audit queries are O(1) instead of recursing through
-- parent_jti at read time. Issue #81.
--
-- Both columns are nullable. Pre-migration credentials and signals
-- stay NULL and remain reachable via the existing parent_jti walk;
-- they age out via TTL with no backfill.
--
-- Each column gets its own btree index so `WHERE mission_id = ?`
-- equality lookups (the only query shape) hit the index.

ALTER TABLE issued_credentials
    ADD COLUMN IF NOT EXISTS mission_id VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_issued_credentials_mission_id
    ON issued_credentials (mission_id)
    WHERE mission_id IS NOT NULL;

ALTER TABLE cae_signals
    ADD COLUMN IF NOT EXISTS mission_id VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_cae_signals_mission_id
    ON cae_signals (mission_id)
    WHERE mission_id IS NOT NULL;
