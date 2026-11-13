-- 069_service_key_management_mark.down.sql
-- Restore 066's audit function first: it reads NEW.management, and with no
-- exception handler a missing column would fail every key insert.
CREATE OR REPLACE FUNCTION create_service_key_audit_log()
RETURNS trigger
LANGUAGE plpgsql
AS $BODY$
BEGIN
    IF TG_WHEN <> 'AFTER' THEN
        RAISE EXCEPTION 'create_service_key_audit_log() may only run as an AFTER trigger';
    END IF;

    IF TG_OP = 'INSERT' THEN
        INSERT INTO identity_audit_logs (
            account_id, project_id, caller_user_id, identity_id,
            table_name, action, status, old_data, new_data, created_at
        ) VALUES (
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
            account_id, project_id, caller_user_id, identity_id,
            table_name, action, status, old_data, new_data, created_at
        ) VALUES (
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

    RETURN NULL;
END;
$BODY$;

ALTER TABLE service_keys DROP COLUMN IF EXISTS management;
