-- 069_service_key_management_mark.up.sql
-- Records that an API key was marked for management by a caller marked with
-- WithManagementKeyWrite (ADR 0053 D3). ZeroID only stores the mark; the
-- embedding service decides what a marked key may do and checks its creator's
-- role on each call.
--
-- A constant default keeps the ADD COLUMN metadata-only; existing keys read
-- as unmarked.
SET LOCAL lock_timeout = '3s';

ALTER TABLE service_keys
    ADD COLUMN IF NOT EXISTS management BOOLEAN NOT NULL DEFAULT false;

-- The audit feed says which keys were created or revoked as management keys.
-- As 066, plus 'management'.
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
                'expires_at', NEW.expires_at,
                'management', NEW.management
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
                'revoke_reason', NEW.revoke_reason,
                'management', NEW.management
            ),
            current_timestamp
        );
    END IF;

    RETURN NULL;
END;
$BODY$;
