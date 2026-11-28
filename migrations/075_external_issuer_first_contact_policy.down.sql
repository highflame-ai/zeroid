-- 075_external_issuer_first_contact_policy.down.sql
-- Restores the 069 audit function (it no longer reads the column) and the
-- 069 CHECK constraint, then drops the column. The constraint is replaced
-- before the column goes: dropping a column drops every table constraint
-- that names it, which would take the whole first-contact check with it.
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
                'claim_constraints', OLD.claim_constraints, 'enabled', OLD.enabled,
                'first_contact', OLD.first_contact,
                'first_contact_project_id', OLD.first_contact_project_id,
                'first_contact_owner_user_id', OLD.first_contact_owner_user_id);
        END IF;
        IF TG_OP <> 'DELETE' THEN
            new_doc := jsonb_build_object(
                'id', NEW.id, 'issuer', NEW.issuer, 'kind', NEW.kind,
                'jwks_uri', NEW.jwks_uri, 'audiences', to_jsonb(NEW.audiences),
                'claim_constraints', NEW.claim_constraints, 'enabled', NEW.enabled,
                'source', NEW.source, 'source_ref', NEW.source_ref,
                'first_contact', NEW.first_contact,
                'first_contact_project_id', NEW.first_contact_project_id,
                'first_contact_owner_user_id', NEW.first_contact_owner_user_id);
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

ALTER TABLE external_issuers DROP CONSTRAINT IF EXISTS external_issuers_first_contact_check;
ALTER TABLE external_issuers ADD CONSTRAINT external_issuers_first_contact_check CHECK (
    first_contact IN ('off', 'discover', 'adopt')
    AND (first_contact = 'off' OR first_contact_project_id <> '')
    AND (first_contact <> 'adopt' OR first_contact_owner_user_id <> '')
);

ALTER TABLE external_issuers DROP COLUMN IF EXISTS first_contact_credential_policy_id;
