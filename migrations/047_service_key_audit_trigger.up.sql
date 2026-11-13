-- 047_service_key_audit_trigger.up.sql
-- Audit key creation and revocation (#391). identity_id is the key's owning
-- identity, which the per-identity audit view filters on. Never copy key_hash.
--
-- CREATE TRIGGER takes SHARE ROW EXCLUSIVE on a hot table; lock_timeout bounds
-- the queue wait. A timeout leaves (47, dirty): recover with `migrate force 46`.
SET LOCAL lock_timeout = '3s';

-- Who performed the creation. created_by names who the key acts for, which on
-- a rotation is the owner, not the operator (rotationAttribution).
ALTER TABLE service_keys ADD COLUMN IF NOT EXISTS created_actor TEXT NOT NULL DEFAULT '';

CREATE OR REPLACE FUNCTION create_service_key_audit_log()
RETURNS trigger
LANGUAGE plpgsql
AS $BODY$
BEGIN
    IF TG_WHEN <> 'AFTER' THEN
        RAISE EXCEPTION 'create_service_key_audit_log() may only run as an AFTER trigger';
    END IF;

    BEGIN
        IF TG_OP = 'INSERT' THEN
            INSERT INTO identity_audit_logs (
                id, account_id, project_id, caller_user_id, identity_id,
                table_name, action, status, old_data, new_data, created_at
            ) VALUES (
                gen_random_uuid(),
                NEW.account_id,
                COALESCE(NEW.project_id, ''),
                LEFT(COALESCE(NULLIF(NEW.created_actor, ''), NEW.created_by, ''), 255),
                COALESCE(NEW.identity_id::text, ''),
                TG_TABLE_NAME,
                'CREATE_KEY',
                'SUCCESS',
                NULL,
                jsonb_build_object(
                    'key_id', NEW.id,
                    'name', NEW.name,
                    'key_prefix', NEW.key_prefix,
                    'product', NEW.product,
                    'state', NEW.state,
                    'expires_at', NEW.expires_at
                ),
                current_timestamp
            );

        ELSIF TG_OP = 'UPDATE' THEN
            INSERT INTO identity_audit_logs (
                id, account_id, project_id, caller_user_id, identity_id,
                table_name, action, status, old_data, new_data, created_at
            ) VALUES (
                gen_random_uuid(),
                NEW.account_id,
                COALESCE(NEW.project_id, ''),
                LEFT(COALESCE(NEW.revoked_by, ''), 255),
                COALESCE(NEW.identity_id::text, ''),
                TG_TABLE_NAME,
                'REVOKE_KEY',
                'SUCCESS',
                jsonb_build_object('key_id', OLD.id, 'state', OLD.state),
                jsonb_build_object(
                    'key_id', NEW.id,
                    'name', NEW.name,
                    'key_prefix', NEW.key_prefix,
                    'product', NEW.product,
                    'state', NEW.state,
                    'revoke_reason', NEW.revoke_reason
                ),
                current_timestamp
            );
        END IF;

    EXCEPTION WHEN OTHERS THEN
        -- Same policy as create_identity_audit_log: an audit failure must
        -- not roll back the revoke itself.
        RAISE WARNING 'Audit logging failed for table %: %', TG_TABLE_NAME, SQLERRM;
    END;

    RETURN NULL;
END;
$BODY$;

DROP TRIGGER IF EXISTS service_key_audit_insert_trigger ON service_keys;
CREATE TRIGGER service_key_audit_insert_trigger
    AFTER INSERT ON service_keys
    FOR EACH ROW EXECUTE FUNCTION create_service_key_audit_log();

-- Only the revoke flip: every key validation updates usage_count, so an
-- unrestricted UPDATE trigger would write one audit row per request.
DROP TRIGGER IF EXISTS service_key_audit_revoke_trigger ON service_keys;
CREATE TRIGGER service_key_audit_revoke_trigger
    AFTER UPDATE OF state ON service_keys
    FOR EACH ROW
    WHEN (OLD.state IS DISTINCT FROM NEW.state AND NEW.state = 'revoked')
    EXECUTE FUNCTION create_service_key_audit_log();
