-- 008_identity_audit_logs.up.sql
-- Records who performed each identity create/update/delete operation.
-- caller_user_id is the acting user (from X-User-ID header), not the identity's owner_user_id.

CREATE TABLE IF NOT EXISTS identity_audit_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id      VARCHAR(255) NOT NULL,
    project_id      VARCHAR(255) NOT NULL DEFAULT '',
    caller_user_id  VARCHAR(255) NOT NULL DEFAULT '',
    identity_id     VARCHAR(255) NOT NULL DEFAULT '',
    action          VARCHAR(50)  NOT NULL,
    status          VARCHAR(50)  NOT NULL DEFAULT 'SUCCESS',
    old_data        JSONB,
    new_data        JSONB,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_identity_audit_logs_tenant
    ON identity_audit_logs (account_id, project_id);

CREATE INDEX IF NOT EXISTS idx_identity_audit_logs_caller
    ON identity_audit_logs (caller_user_id)
    WHERE caller_user_id != '';
