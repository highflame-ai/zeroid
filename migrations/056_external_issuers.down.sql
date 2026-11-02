-- WARNING: this drops every trusted issuer and binding an operator
-- configured; nothing can restore them. Roll the binary back first: a
-- server still running this branch reads these tables on every federated
-- grant (and with federation.issuer_store=db cannot serve one without them).
SET LOCAL lock_timeout = '3s';

DROP TRIGGER IF EXISTS external_issuer_bindings_audit_trigger ON external_issuer_bindings;
DROP TRIGGER IF EXISTS external_issuers_audit_trigger ON external_issuers;
DROP FUNCTION IF EXISTS create_external_issuer_audit_log();
DROP TABLE IF EXISTS external_issuer_bindings;
DROP TABLE IF EXISTS external_issuers;
