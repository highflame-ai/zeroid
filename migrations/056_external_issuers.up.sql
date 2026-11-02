-- 056_external_issuers.up.sql
-- Per-account trusted issuers and credential bindings (ADR 0042 D4, D6).
-- docs/external-issuers.md describes the model; this file only states the
-- constraints the database holds itself.
--
-- Ordering: 055 (refresh-token family, PRs #421-#423) must be applied before
-- this. golang-migrate never applies a version below the current one, so a
-- database that reached 056 first would skip 055. If this lands first,
-- renumber at merge.
--
-- Edited in place before release (soft deletes, explicitly_disabled, length
-- checks, the canonical-issuer index): a dev database that ran an earlier
-- 056 must be re-created, or `migrate force 55` and re-run.
--
-- New, empty tables: no rewrite or backfill. lock_timeout bounds the FK
-- validation's brief lock on identities. A timeout leaves (56, dirty):
-- recover with `migrate force 55` (the previous version) and retry.
--
-- Rows are soft-deleted (deleted_at); every unique index covers live rows
-- only, so a deleted issuer can be trusted again.
SET LOCAL lock_timeout = '3s';

CREATE TABLE IF NOT EXISTS external_issuers (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id              VARCHAR(255)  NOT NULL,
    -- Bytes, not characters, bound the btree entries (about 2.7 kB max).
    issuer                  VARCHAR(2048) NOT NULL CHECK (octet_length(issuer) <= 2000),
    kind                    VARCHAR(16)   NOT NULL CHECK (kind IN ('person', 'workload')),
    display_name            VARCHAR(255)  NOT NULL DEFAULT '',
    jwks_uri                VARCHAR(2048) NOT NULL CHECK (octet_length(jwks_uri) <= 2000),
    -- A person row may have none: bindings admit the agents' client ids.
    audiences               TEXT[]        NOT NULL CHECK (kind = 'person' OR cardinality(audiences) > 0),
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
    updated_at              TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    deleted_at              TIMESTAMPTZ
);

-- Uniqueness compares issuers without trailing slashes, so "https://x/"
-- and "https://x" are one issuer. Overlapping shared-issuer constraints are
-- checked by the writer under the advisory lock.
CREATE UNIQUE INDEX IF NOT EXISTS external_issuers_issuer_kind_constraints_uq
    ON external_issuers (rtrim(issuer, '/'), kind, constraints_key) WHERE deleted_at IS NULL;
-- The per-grant lookup matches a token's iss exactly.
CREATE INDEX IF NOT EXISTS external_issuers_issuer_idx
    ON external_issuers (issuer) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS external_issuers_account_idx
    ON external_issuers (account_id) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS external_issuer_bindings (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id   VARCHAR(255)  NOT NULL,
    -- Issuer rows are never hard-deleted (deleted_at), so no cascade.
    issuer_id    UUID          NOT NULL REFERENCES external_issuers (id),
    subject_key  VARCHAR(2048) NOT NULL CHECK (octet_length(subject_key) <= 2000),
    -- Identities are deactivated, not deleted; only a purge of a
    -- never-adopted discovered identity hard-deletes one, and its bindings
    -- go with it (the audit trigger records the delete).
    identity_id  UUID          NOT NULL REFERENCES identities (id) ON DELETE CASCADE,
    enabled      BOOLEAN       NOT NULL DEFAULT FALSE,
    -- True once an admin disabled the binding (or created it disabled), as
    -- opposed to disabled only because its identity was not active yet. The
    -- deployer enables at adoption only bindings where this is false.
    explicitly_disabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_by   VARCHAR(255)  NOT NULL DEFAULT '',
    updated_by   VARCHAR(255)  NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    deleted_at   TIMESTAMPTZ
);

-- Also the per-grant lookup index, by its (issuer_id, subject_key) prefix.
CREATE UNIQUE INDEX IF NOT EXISTS external_issuer_bindings_identity_uq
    ON external_issuer_bindings (issuer_id, subject_key, identity_id) WHERE deleted_at IS NULL;
-- D6: at most one enabled binding per (issuer, subject key).
CREATE UNIQUE INDEX IF NOT EXISTS external_issuer_bindings_enabled_uq
    ON external_issuer_bindings (issuer_id, subject_key) WHERE enabled AND deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS external_issuer_bindings_account_idx
    ON external_issuer_bindings (account_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS external_issuer_bindings_identity_idx
    ON external_issuer_bindings (identity_id) WHERE deleted_at IS NULL;

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

DROP TRIGGER IF EXISTS external_issuers_audit_trigger ON external_issuers;
CREATE TRIGGER external_issuers_audit_trigger
    AFTER INSERT OR UPDATE OR DELETE ON external_issuers
    FOR EACH ROW EXECUTE FUNCTION create_external_issuer_audit_log();

DROP TRIGGER IF EXISTS external_issuer_bindings_audit_trigger ON external_issuer_bindings;
CREATE TRIGGER external_issuer_bindings_audit_trigger
    AFTER INSERT OR UPDATE OR DELETE ON external_issuer_bindings
    FOR EACH ROW EXECUTE FUNCTION create_external_issuer_audit_log();
