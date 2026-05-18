-- 020_ciba_ping_columns.up.sql
-- CIBA Core 1.0 ping mode adds two pieces of state:
--
--   1. oauth_clients.client_notification_endpoint — the registered HTTPS URL
--      the server POSTs to when a bc-authorize request resolves. Registered
--      at client-registration time so the URL acts as a per-client
--      allowlist; bc-authorize requests in ping mode reuse whatever is on
--      the client record (the client cannot supply an arbitrary endpoint
--      per-request — that would defeat the allowlist).
--
--   2. backchannel_auth_requests.client_notification_token — a per-request
--      bearer the *client* supplies on bc-authorize. The server echoes it
--      back unchanged in the ping callback's Authorization header so the
--      client can authenticate the inbound notification (CIBA Core §10.2).
--      Length-capped at 1024 bytes — the spec doesn't bound it, but
--      anything beyond that is almost certainly an injection attempt.

ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS client_notification_endpoint TEXT NOT NULL DEFAULT '';

ALTER TABLE backchannel_auth_requests
    ADD COLUMN IF NOT EXISTS client_notification_token VARCHAR(1024);
