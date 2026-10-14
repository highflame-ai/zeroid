SET LOCAL lock_timeout = '3s';

DROP TRIGGER IF EXISTS external_issuer_bindings_audit_trigger ON external_issuer_bindings;
DROP TRIGGER IF EXISTS external_issuers_audit_trigger ON external_issuers;
DROP FUNCTION IF EXISTS create_external_issuer_audit_log();
DROP TABLE IF EXISTS external_issuer_bindings;
DROP TABLE IF EXISTS external_issuers;
