SET LOCAL lock_timeout = '3s';

DROP TRIGGER IF EXISTS service_key_audit_revoke_trigger ON service_keys;
DROP TRIGGER IF EXISTS service_key_audit_insert_trigger ON service_keys;
DROP FUNCTION IF EXISTS create_service_key_audit_log();
ALTER TABLE service_keys DROP COLUMN IF EXISTS created_actor;
