-- 066_identity_audit_feed.up.sql
-- Make identity_audit_logs a log a consumer can follow in order (#483), stop
-- the audit triggers from swallowing their own failures, and audit
-- credential policy changes.
--
-- ORDER. Each row gets the writing transaction's id (txid) and a sequence
-- number (seq). A reader pages by (txid, seq) and only returns rows whose
-- txid is below pg_snapshot_xmin(pg_current_snapshot()): every transaction
-- below that bound has finished, so a row that commits late is never passed
-- over. seq alone is not enough, because sequence values commit out of
-- order. Both are column defaults, not set by the triggers, so direct
-- inserts (AuthN's quarantine audit) get them too. xid8 needs PostgreSQL 13.
--
-- FAIL CLOSED. The trigger functions caught every error (EXCEPTION WHEN
-- OTHERS) and let the change commit without its audit row. They no longer
-- do: a failed audit insert now fails the change.
--
-- BOOKKEEPING. Updates to identities and credential policies that change only
-- updated_at (and, for identities, modified_by) are no longer audited, so
-- connector sync's last-seen bump writes no row (see the triggers below).
--
-- LOCK POSTURE (cf. 045/047). Nullable columns with no default, then SET
-- DEFAULT: both metadata-only, no table rewrite. CREATE TRIGGER takes SHARE
-- ROW EXCLUSIVE on identities and credential_policies. lock_timeout bounds the queue wait;
-- a timeout leaves (66, dirty): recover with `migrate force 65`. Existing
-- rows are numbered in 067.
SET LOCAL lock_timeout = '3s';

ALTER TABLE identity_audit_logs
    ADD COLUMN IF NOT EXISTS txid xid8,
    ADD COLUMN IF NOT EXISTS seq  BIGINT;

CREATE SEQUENCE IF NOT EXISTS identity_audit_logs_seq_seq OWNED BY identity_audit_logs.seq;

ALTER TABLE identity_audit_logs
    ALTER COLUMN txid SET DEFAULT pg_current_xact_id(),
    ALTER COLUMN seq  SET DEFAULT nextval('identity_audit_logs_seq_seq');

-- identities (and any table it was attached to). As 013, without the
-- exception handler; the caller is cut to the column's 255.
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

    IF TG_OP = 'INSERT' THEN
        caller_id := COALESCE(NEW.created_by, '');
        INSERT INTO identity_audit_logs (
            account_id, project_id, caller_user_id, identity_id,
            table_name, action, status, old_data, new_data, created_at
        ) VALUES (
            NEW.account_id, NEW.project_id, LEFT(caller_id, 255), NEW.id::text,
            TG_TABLE_NAME, 'CREATE', 'SUCCESS', NULL, row_to_json(NEW.*)::jsonb, current_timestamp
        );

    ELSIF TG_OP = 'UPDATE' THEN
        caller_id := COALESCE(NULLIF(NEW.modified_by, ''), NEW.created_by, '');
        INSERT INTO identity_audit_logs (
            account_id, project_id, caller_user_id, identity_id,
            table_name, action, status, old_data, new_data, created_at
        ) VALUES (
            NEW.account_id, NEW.project_id, LEFT(caller_id, 255), NEW.id::text,
            TG_TABLE_NAME, 'UPDATE', 'SUCCESS', row_to_json(OLD.*)::jsonb, row_to_json(NEW.*)::jsonb, current_timestamp
        );

    ELSIF TG_OP = 'DELETE' THEN
        caller_id := COALESCE(NULLIF(OLD.modified_by, ''), OLD.created_by, '');
        INSERT INTO identity_audit_logs (
            account_id, project_id, caller_user_id, identity_id,
            table_name, action, status, old_data, new_data, created_at
        ) VALUES (
            OLD.account_id, OLD.project_id, LEFT(caller_id, 255), OLD.id::text,
            TG_TABLE_NAME, 'DELETE', 'SUCCESS', row_to_json(OLD.*)::jsonb, NULL, current_timestamp
        );
    END IF;

    RETURN NULL;
END;
$BODY$;

-- service_keys. As 047, without the exception handler.
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

-- external_issuers and external_issuer_bindings. As 056, without the
-- exception handler.
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

-- credential_policies: not audited before. The table has no created_by or
-- modified_by, so the writer names itself through zeroid.audit_actor for the
-- transaction (056's pattern). Rows with no actor are ZeroID's own work: the
-- default policy a tenant gets on first use, and policies derived at
-- adoption. Policies hold no secrets, so the whole row is copied.
CREATE OR REPLACE FUNCTION create_credential_policy_audit_log()
RETURNS trigger
LANGUAGE plpgsql
AS $BODY$
DECLARE
    rec RECORD;
BEGIN
    IF TG_WHEN <> 'AFTER' THEN
        RAISE EXCEPTION 'create_credential_policy_audit_log() may only run as an AFTER trigger';
    END IF;

    IF TG_OP = 'DELETE' THEN
        rec := OLD;
    ELSE
        rec := NEW;
    END IF;

    INSERT INTO identity_audit_logs (
        account_id, project_id, caller_user_id, identity_id,
        table_name, action, status, old_data, new_data, created_at
    ) VALUES (
        rec.account_id,
        rec.project_id,
        LEFT(COALESCE(current_setting('zeroid.audit_actor', true), ''), 255),
        '',
        TG_TABLE_NAME,
        CASE TG_OP WHEN 'INSERT' THEN 'CREATE' ELSE TG_OP END,
        'SUCCESS',
        CASE WHEN TG_OP <> 'INSERT' THEN to_jsonb(OLD) END,
        CASE WHEN TG_OP <> 'DELETE' THEN to_jsonb(NEW) END,
        current_timestamp
    );

    RETURN NULL;
END;
$BODY$;

-- Updates are audited only when a column other than bookkeeping changed:
-- updated_at, which connector sync bumps on every pass (045), and
-- modified_by, which names who acted rather than what changed. An update
-- trigger's WHEN can compare OLD and NEW; an insert or delete trigger's
-- cannot, so each table gets two triggers.
DROP TRIGGER IF EXISTS credential_policy_audit_trigger ON credential_policies;
CREATE TRIGGER credential_policy_audit_trigger
    AFTER INSERT OR DELETE ON credential_policies
    FOR EACH ROW EXECUTE FUNCTION create_credential_policy_audit_log();
DROP TRIGGER IF EXISTS credential_policy_audit_update_trigger ON credential_policies;
CREATE TRIGGER credential_policy_audit_update_trigger
    AFTER UPDATE ON credential_policies
    FOR EACH ROW
    WHEN ((to_jsonb(OLD) - 'updated_at') IS DISTINCT FROM (to_jsonb(NEW) - 'updated_at'))
    EXECUTE FUNCTION create_credential_policy_audit_log();

DROP TRIGGER IF EXISTS identity_audit_trigger ON identities;
CREATE TRIGGER identity_audit_trigger
    AFTER INSERT OR DELETE ON identities
    FOR EACH ROW EXECUTE FUNCTION create_identity_audit_log();
DROP TRIGGER IF EXISTS identity_audit_update_trigger ON identities;
CREATE TRIGGER identity_audit_update_trigger
    AFTER UPDATE ON identities
    FOR EACH ROW
    WHEN ((to_jsonb(OLD) - 'updated_at' - 'modified_by') IS DISTINCT FROM (to_jsonb(NEW) - 'updated_at' - 'modified_by'))
    EXECUTE FUNCTION create_identity_audit_log();
