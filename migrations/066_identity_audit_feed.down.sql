-- 066_identity_audit_feed.down.sql
-- Restores the 013/047/056 trigger functions, which catch their own errors,
-- and drops credential policy auditing and the feed columns. Locks are taken
-- up front in a live write's order, as in the up file.
SET LOCAL lock_timeout = '3s';

LOCK TABLE identities, credential_policies, identity_audit_logs IN ACCESS EXCLUSIVE MODE;

DROP TRIGGER IF EXISTS credential_policy_audit_update_trigger ON credential_policies;
DROP TRIGGER IF EXISTS credential_policy_audit_trigger ON credential_policies;
DROP FUNCTION IF EXISTS create_credential_policy_audit_log();

DROP TRIGGER IF EXISTS identity_audit_update_trigger ON identities;
DROP TRIGGER IF EXISTS identity_audit_trigger ON identities;
CREATE TRIGGER identity_audit_trigger
    AFTER INSERT OR UPDATE OR DELETE ON identities
    FOR EACH ROW EXECUTE FUNCTION create_identity_audit_log();

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

CREATE OR REPLACE FUNCTION create_external_issuer_audit_log()
RETURNS trigger
LANGUAGE plpgsql
AS $BODY$
DECLARE
    rec       RECORD;
    actor     TEXT;
    action    TEXT;
    old_doc   JSONB;
    new_doc   JSONB;
    ident     TEXT := '';
BEGIN
    IF TG_WHEN <> 'AFTER' THEN
        RAISE EXCEPTION 'create_external_issuer_audit_log() may only run as an AFTER trigger';
    END IF;

    BEGIN
        IF TG_OP = 'DELETE' THEN
            rec := OLD;
        ELSE
            rec := NEW;
        END IF;

        action := TG_OP;
        IF TG_OP = 'UPDATE' AND NEW.deleted_at IS NOT NULL AND OLD.deleted_at IS NULL THEN
            action := 'DELETE';
        END IF;

        IF TG_TABLE_NAME = 'external_issuers' THEN
            action := action || '_EXTERNAL_ISSUER';
            IF TG_OP <> 'INSERT' THEN
                old_doc := jsonb_build_object(
                    'id', OLD.id, 'issuer', OLD.issuer, 'kind', OLD.kind,
                    'jwks_uri', OLD.jwks_uri, 'audiences', to_jsonb(OLD.audiences),
                    'claim_constraints', OLD.claim_constraints, 'enabled', OLD.enabled);
            END IF;
            IF TG_OP <> 'DELETE' THEN
                new_doc := jsonb_build_object(
                    'id', NEW.id, 'issuer', NEW.issuer, 'kind', NEW.kind,
                    'jwks_uri', NEW.jwks_uri, 'audiences', to_jsonb(NEW.audiences),
                    'claim_constraints', NEW.claim_constraints, 'enabled', NEW.enabled,
                    'source', NEW.source, 'source_ref', NEW.source_ref);
            END IF;
        ELSE
            action := action || '_ISSUER_BINDING';
            ident := rec.identity_id::text;
            IF TG_OP <> 'INSERT' THEN
                old_doc := jsonb_build_object(
                    'id', OLD.id, 'issuer_id', OLD.issuer_id, 'subject_key', OLD.subject_key,
                    'identity_id', OLD.identity_id, 'enabled', OLD.enabled,
                    'explicitly_disabled', OLD.explicitly_disabled);
            END IF;
            IF TG_OP <> 'DELETE' THEN
                new_doc := jsonb_build_object(
                    'id', NEW.id, 'issuer_id', NEW.issuer_id, 'subject_key', NEW.subject_key,
                    'identity_id', NEW.identity_id, 'enabled', NEW.enabled,
                    'explicitly_disabled', NEW.explicitly_disabled);
            END IF;
        END IF;

        actor := NULLIF(current_setting('zeroid.audit_actor', true), '');
        IF actor IS NULL THEN
            actor := COALESCE(rec.updated_by, '');
        END IF;

        INSERT INTO identity_audit_logs (
            id, account_id, project_id, caller_user_id, identity_id,
            table_name, action, status, old_data, new_data, created_at
        ) VALUES (
            gen_random_uuid(),
            rec.account_id,
            '',
            LEFT(actor, 255),
            ident,
            TG_TABLE_NAME,
            action,
            'SUCCESS',
            old_doc,
            new_doc,
            current_timestamp
        );
    EXCEPTION WHEN OTHERS THEN
        -- Same policy as 047: an audit failure must not roll back the write.
        RAISE WARNING 'Audit logging failed for table %: %', TG_TABLE_NAME, SQLERRM;
    END;

    RETURN NULL;
END;
$BODY$;

ALTER TABLE identity_audit_logs
    DROP COLUMN IF EXISTS seq,
    DROP COLUMN IF EXISTS txid;
DROP SEQUENCE IF EXISTS identity_audit_logs_seq_seq;
