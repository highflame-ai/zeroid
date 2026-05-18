-- 021_ciba_push_mode.up.sql
-- OpenID CIBA Core 1.0 §10: token delivery modes.
--
-- A client declares its supported delivery mode at registration:
--
--   poll  — client polls /oauth2/token with the auth_req_id (PR 1).
--   ping  — server POSTs auth_req_id to client_notification_endpoint on
--           resolution; client then polls /oauth2/token for the token (PR 2).
--   push  — server POSTs the full token response (access_token + metadata)
--           to client_notification_endpoint on resolution; client never polls
--           (PR 3 — this migration).
--
-- Per §10 the mode is a property of the client, not the request, so the
-- enum lives on oauth_clients. A bc-authorize request from a push-mode
-- client must supply client_notification_token (same as ping); the
-- server then delivers the token via callback and refuses any subsequent
-- polling of the same auth_req_id.

ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS backchannel_token_delivery_mode
        VARCHAR(8) NOT NULL DEFAULT 'poll'
        CHECK (backchannel_token_delivery_mode IN ('poll', 'ping', 'push'));
