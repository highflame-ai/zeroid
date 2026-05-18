-- 014_backchannel_auth_requests.up.sql
-- OpenID CIBA Core 1.0 — pending backchannel authentication requests.
--
-- A client calls POST /oauth2/bc-authorize with a login_hint and binding_message;
-- ZeroID persists the request with status='pending' and (optionally) fires a
-- BackchannelNotifier so the deployer can deliver an out-of-band approval prompt.
-- The user (via a deployer-controlled UX in front of the admin API) calls
-- POST /oauth2/bc-authorize/{auth_req_id}/approve or /deny. The client polls
-- /oauth2/token with grant_type=urn:openid:params:grant-type:ciba; the response
-- is authorization_pending / slow_down / access_denied / expired_token until
-- the row transitions to status='approved', at which point a normal access
-- token is minted through the usual credential pipeline.
--
-- Columns reserved up-front for ping mode (PR 2): notification_mode and
-- client_notification_endpoint. They are nullable / defaulted so PR 1's
-- polling-only code path leaves them untouched.

CREATE TABLE IF NOT EXISTS backchannel_auth_requests (
    auth_req_id                  VARCHAR(255) PRIMARY KEY,
    account_id                   VARCHAR(255) NOT NULL,
    project_id                   VARCHAR(255) NOT NULL DEFAULT '',
    client_id                    VARCHAR(255) NOT NULL,
    login_hint                   TEXT,
    scope                        TEXT NOT NULL DEFAULT '',
    binding_message              TEXT,
    notification_mode            VARCHAR(16)  NOT NULL DEFAULT 'poll',
    client_notification_endpoint TEXT,
    status                       VARCHAR(16)  NOT NULL DEFAULT 'pending',
    approved_subject_id          VARCHAR(255),
    approved_subject_email       VARCHAR(255),
    approved_subject_name        VARCHAR(255),
    interval_seconds             INT          NOT NULL DEFAULT 5,
    last_polled_at               TIMESTAMPTZ,
    last_notify_error            TEXT,
    expires_at                   TIMESTAMPTZ  NOT NULL,
    created_at                   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    approved_at                  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_bc_status_expires_at
    ON backchannel_auth_requests (status, expires_at);

CREATE INDEX IF NOT EXISTS idx_bc_tenant
    ON backchannel_auth_requests (account_id, project_id);
