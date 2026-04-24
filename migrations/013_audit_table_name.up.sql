-- 013_audit_table_name.up.sql
-- Adds table_name to identity_audit_logs so the table can receive audit entries
-- from multiple source tables (credential_policies, service_keys, oauth_clients).
-- The trigger reads TG_TABLE_NAME instead of hardcoding 'identities'.

ALTER TABLE identity_audit_logs
    ADD COLUMN IF NOT EXISTS table_name VARCHAR(255) NOT NULL DEFAULT 'identities';

CREATE INDEX IF NOT EXISTS idx_identity_audit_logs_table_name
    ON identity_audit_logs (table_name);

-- Update the trigger function to write TG_TABLE_NAME instead of a hardcoded value.
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
                table_name, action, status, old_data, new_data, created_at
            ) VALUES (
                gen_random_uuid(),
                NEW.account_id,
                NEW.project_id,
                caller_id,
                NEW.id::text,
                TG_TABLE_NAME,
                'CREATE',
                'SUCCESS',
                NULL,
                row_to_json(NEW.*)::jsonb,
                current_timestamp
            );

        ELSIF TG_OP = 'UPDATE' THEN
            caller_id := COALESCE(NULLIF(NEW.modified_by, ''), NEW.created_by, '');
            INSERT INTO identity_audit_logs (
                id, account_id, project_id, caller_user_id, identity_id,
                table_name, action, status, old_data, new_data, created_at
            ) VALUES (
                gen_random_uuid(),
                NEW.account_id,
                NEW.project_id,
                caller_id,
                NEW.id::text,
                TG_TABLE_NAME,
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
                table_name, action, status, old_data, new_data, created_at
            ) VALUES (
                gen_random_uuid(),
                OLD.account_id,
                OLD.project_id,
                caller_id,
                OLD.id::text,
                TG_TABLE_NAME,
                'DELETE',
                'SUCCESS',
                row_to_json(OLD.*)::jsonb,
                NULL,
                current_timestamp
            );
        END IF;

    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE 'Audit logging failed for table %: %', TG_TABLE_NAME, SQLERRM;
    END;

    RETURN NULL;
END;
$BODY$;
