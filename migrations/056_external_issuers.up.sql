-- 056_external_issuers.up.sql
-- Per-account trusted issuers and credential bindings (ADR 0042 D4, D6).
-- docs/external-issuers.md describes the model; this file only states the
-- constraints the database holds itself.
--
-- New, empty tables: no rewrite or backfill. lock_timeout bounds the FK
-- validation's brief lock on identities.
SET LOCAL lock_timeout = '3s';

CREATE TABLE IF NOT EXISTS external_issuers (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id              VARCHAR(255)  NOT NULL,
    issuer                  VARCHAR(2048) NOT NULL,
    kind                    VARCHAR(16)   NOT NULL CHECK (kind IN ('person', 'workload')),
    display_name            VARCHAR(255)  NOT NULL DEFAULT '',
    jwks_uri                VARCHAR(2048) NOT NULL,
    audiences               TEXT[]        NOT NULL CHECK (cardinality(audiences) > 0),
    algorithms              TEXT[]        NOT NULL CHECK (cardinality(algorithms) > 0),
    claim_mapping           JSONB         NOT NULL DEFAULT '{}'::jsonb,
    propagate_claims        TEXT[]        NOT NULL DEFAULT '{}',
    claim_constraints       JSONB         NOT NULL DEFAULT '{}'::jsonb,
    -- '' for a customer-unique issuer, so the unique index below allows one
    -- row per kind; a hash of claim_constraints for a shared issuer.
    constraints_key         VARCHAR(64)   NOT NULL DEFAULT '',
    max_token_age_seconds   INTEGER       NOT NULL DEFAULT 600 CHECK (max_token_age_seconds BETWEEN 1 AND 3600),
    jwks_cache_ttl_seconds  INTEGER       NOT NULL DEFAULT 300 CHECK (jwks_cache_ttl_seconds BETWEEN 30 AND 86400),
    source                  VARCHAR(16)   NOT NULL DEFAULT 'admin' CHECK (source IN ('admin', 'connector')),
    source_ref              VARCHAR(255)  NOT NULL DEFAULT '',
    enabled                 BOOLEAN       NOT NULL DEFAULT TRUE,
    created_by              VARCHAR(255)  NOT NULL DEFAULT '',
    updated_by              VARCHAR(255)  NOT NULL DEFAULT '',
    created_at              TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- Also the per-grant lookup index (issuer is its leading column).
CREATE UNIQUE INDEX IF NOT EXISTS external_issuers_issuer_kind_constraints_uq
    ON external_issuers (issuer, kind, constraints_key);
CREATE INDEX IF NOT EXISTS external_issuers_account_idx
    ON external_issuers (account_id);

CREATE TABLE IF NOT EXISTS external_issuer_bindings (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id   VARCHAR(255)  NOT NULL,
    issuer_id    UUID          NOT NULL REFERENCES external_issuers (id) ON DELETE CASCADE,
    subject_key  VARCHAR(2048) NOT NULL,
    identity_id  UUID          NOT NULL REFERENCES identities (id) ON DELETE CASCADE,
    enabled      BOOLEAN       NOT NULL DEFAULT FALSE,
    created_by   VARCHAR(255)  NOT NULL DEFAULT '',
    updated_by   VARCHAR(255)  NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS external_issuer_bindings_identity_uq
    ON external_issuer_bindings (issuer_id, subject_key, identity_id);
-- D6: at most one enabled binding per (issuer, subject key). Also the
-- per-grant lookup index.
CREATE UNIQUE INDEX IF NOT EXISTS external_issuer_bindings_enabled_uq
    ON external_issuer_bindings (issuer_id, subject_key) WHERE enabled;
CREATE INDEX IF NOT EXISTS external_issuer_bindings_account_idx
    ON external_issuer_bindings (account_id);
CREATE INDEX IF NOT EXISTS external_issuer_bindings_identity_idx
    ON external_issuer_bindings (identity_id);

-- Audit, in the 047 pattern. The writer sets zeroid.audit_actor for the
-- transaction, which is the only way a DELETE can name who made it.
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

        IF TG_TABLE_NAME = 'external_issuers' THEN
            action := TG_OP || '_EXTERNAL_ISSUER';
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
            action := TG_OP || '_ISSUER_BINDING';
            ident := rec.identity_id::text;
            IF TG_OP <> 'INSERT' THEN
                old_doc := jsonb_build_object(
                    'id', OLD.id, 'issuer_id', OLD.issuer_id, 'subject_key', OLD.subject_key,
                    'identity_id', OLD.identity_id, 'enabled', OLD.enabled);
            END IF;
            IF TG_OP <> 'DELETE' THEN
                new_doc := jsonb_build_object(
                    'id', NEW.id, 'issuer_id', NEW.issuer_id, 'subject_key', NEW.subject_key,
                    'identity_id', NEW.identity_id, 'enabled', NEW.enabled);
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

DROP TRIGGER IF EXISTS external_issuers_audit_trigger ON external_issuers;
CREATE TRIGGER external_issuers_audit_trigger
    AFTER INSERT OR UPDATE OR DELETE ON external_issuers
    FOR EACH ROW EXECUTE FUNCTION create_external_issuer_audit_log();

DROP TRIGGER IF EXISTS external_issuer_bindings_audit_trigger ON external_issuer_bindings;
CREATE TRIGGER external_issuer_bindings_audit_trigger
    AFTER INSERT OR UPDATE OR DELETE ON external_issuer_bindings
    FOR EACH ROW EXECUTE FUNCTION create_external_issuer_audit_log();
