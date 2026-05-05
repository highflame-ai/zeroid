-- 010_identity_audit_trigger.up.sql
-- PostgreSQL AFTER trigger on identities → writes to identity_audit_logs automatically.
-- Matches the admin service audit pattern (create_audit_log_on_modify) but targets
-- identity_audit_logs and reads from identities-specific columns.
--
-- caller_user_id is sourced from:
--   INSERT: NEW.created_by
--   UPDATE: NEW.modified_by (set by the application from X-User-ID header)
--   DELETE: OLD.modified_by (set by the application just before deleting)

CREATE OR REPLACE FUNCTION create_identity_audit_log()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
AS $BODY$
DECLARE
    caller_id text;
BEGIN
    IF TG_WHEN <> 'AFTER' THEN
        RAISE EXCEPTION 'create_identity_audit_log() may only run as an AFTER trigger';
    END IF;

    BEGIN
        IF TG_OP = 'INSERT' THEN
            caller_id := COALESCE(NEW.created_by, '');
            INSERT INTO identity_audit_logs (
                id, account_id, project_id, caller_user_id, identity_id,
                action, status, old_data, new_data, created_at
            ) VALUES (
                gen_random_uuid(),
                NEW.account_id,
                NEW.project_id,
                caller_id,
                NEW.id::text,
                'CREATE',
                'SUCCESS',
                NULL,
                row_to_json(NEW.*)::jsonb,
                current_timestamp
            );

        ELSIF TG_OP = 'UPDATE' THEN
            -- Prefer modified_by; fall back to created_by if not yet set.
            caller_id := COALESCE(NULLIF(NEW.modified_by, ''), NEW.created_by, '');
            INSERT INTO identity_audit_logs (
                id, account_id, project_id, caller_user_id, identity_id,
                action, status, old_data, new_data, created_at
            ) VALUES (
                gen_random_uuid(),
                NEW.account_id,
                NEW.project_id,
                caller_id,
                NEW.id::text,
                'UPDATE',
                'SUCCESS',
                row_to_json(OLD.*)::jsonb,
                row_to_json(NEW.*)::jsonb,
                current_timestamp
            );

        ELSIF TG_OP = 'DELETE' THEN
            caller_id := COALESCE(NULLIF(OLD.modified_by, ''), OLD.created_by, '');
            INSERT INTO identity_audit_logs (
                id, account_id, project_id, caller_user_id, identity_id,
                action, status, old_data, new_data, created_at
            ) VALUES (
                gen_random_uuid(),
                OLD.account_id,
                OLD.project_id,
                caller_id,
                OLD.id::text,
                'DELETE',
                'SUCCESS',
                row_to_json(OLD.*)::jsonb,
                NULL,
                current_timestamp
            );
        END IF;

    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE 'Identity audit logging failed: %', SQLERRM;
    END;

    RETURN NULL;
END;
$BODY$;

CREATE TRIGGER identity_audit_trigger
    AFTER INSERT OR UPDATE OR DELETE ON identities
    FOR EACH ROW EXECUTE FUNCTION create_identity_audit_log();
