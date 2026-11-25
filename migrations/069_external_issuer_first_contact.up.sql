-- 069_external_issuer_first_contact.up.sql
-- First-contact registration on issuer rows. docs/external-issuers.md
-- ("First contact") describes the behaviour; this file only states what the
-- database holds itself.
--
-- first_contact is off, discover or adopt. discover and adopt name the
-- project an agent first seen through the row is registered into; adopt also
-- names its owner, because adopting needs one.
--
-- LOCK POSTURE. Constant defaults add the columns without a table rewrite.
-- The CHECK constraint is validated in place, which scans external_issuers
-- under its ACCESS EXCLUSIVE lock; the table holds a few rows per account,
-- and every existing row is 'off', so the scan is short and cannot fail.
-- The partial index on external_issuer_bindings is built in place too: that
-- table is small, and only rows first contact writes enter the index.
-- lock_timeout bounds the wait for both locks. A timeout leaves (69, dirty):
-- recover with `migrate force 68` and run it again.
SET LOCAL lock_timeout = '3s';

ALTER TABLE external_issuers
    ADD COLUMN IF NOT EXISTS first_contact               VARCHAR(16)  NOT NULL DEFAULT 'off',
    ADD COLUMN IF NOT EXISTS first_contact_project_id    VARCHAR(255) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS first_contact_owner_user_id VARCHAR(255) NOT NULL DEFAULT '';

ALTER TABLE external_issuers DROP CONSTRAINT IF EXISTS external_issuers_first_contact_check;
ALTER TABLE external_issuers ADD CONSTRAINT external_issuers_first_contact_check CHECK (
    first_contact IN ('off', 'discover', 'adopt')
    AND (first_contact = 'off' OR first_contact_project_id <> '')
    AND (first_contact <> 'adopt' OR first_contact_owner_user_id <> '')
);

-- The per-row rate limit counts the bindings first contact created under a
-- row in the last minute.
CREATE INDEX IF NOT EXISTS external_issuer_bindings_first_contact_idx
    ON external_issuer_bindings (issuer_id, created_at)
    WHERE created_by = 'system:first_contact';

-- Audit the first-contact settings with the rest of the row: adopt is an
-- adoption decision, so who switched it on, and with which mapping, is kept.
-- As 066, with the three columns added to the issuer documents.
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
