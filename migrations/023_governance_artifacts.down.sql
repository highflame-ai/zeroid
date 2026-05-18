-- 023_governance_artifacts.down.sql

DROP INDEX IF EXISTS idx_issued_credentials_catalog_hash;
DROP INDEX IF EXISTS idx_issued_credentials_drm_hash;

ALTER TABLE issued_credentials
    DROP COLUMN IF EXISTS constraint_catalog_hash,
    DROP COLUMN IF EXISTS drm_hash;

DROP INDEX IF EXISTS idx_catalog_tenant_effective;
DROP INDEX IF EXISTS idx_catalog_tenant_signed;
DROP TABLE IF EXISTS constraint_catalog_versions;

DROP TRIGGER IF EXISTS drm_block_delete ON decision_rights_matrix;
DROP TRIGGER IF EXISTS drm_block_update ON decision_rights_matrix;
DROP FUNCTION IF EXISTS drm_block_mutation();
DROP INDEX IF EXISTS idx_drm_tenant_effective;
DROP TABLE IF EXISTS decision_rights_matrix;
