-- 069_external_issuer_first_contact.down.sql
-- Restores the 066 audit function first (it no longer reads the columns),
-- then drops the index, the constraint and the columns.
SET LOCAL lock_timeout = '3s';

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
        account_id, project_id, caller_user_id, identity_id,
        table_name, action, status, old_data, new_data, created_at
    ) VALUES (
        rec.account_id, '', LEFT(actor, 255), ident,
        TG_TABLE_NAME, action, 'SUCCESS', old_doc, new_doc, current_timestamp
    );

    RETURN NULL;
END;
$BODY$;

DROP INDEX IF EXISTS external_issuer_bindings_first_contact_idx;

ALTER TABLE external_issuers DROP CONSTRAINT IF EXISTS external_issuers_first_contact_check;

ALTER TABLE external_issuers
    DROP COLUMN IF EXISTS first_contact_owner_user_id,
    DROP COLUMN IF EXISTS first_contact_project_id,
    DROP COLUMN IF EXISTS first_contact;
