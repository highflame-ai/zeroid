-- 023_dynamic_client_registration.up.sql
-- Adds dynamic client registration support per RFC 7591/7592.
--
-- registration_source: 'internal' for clients registered via the admin/internal
--   API path, 'dynamic' for clients registered via POST /oauth2/register (RFC 7591).
--
-- registration_access_token: bcrypt hash of the management bearer token returned
--   at RFC 7591 registration time. NULL for internal clients. Used by RFC 7592
--   GET/PUT/DELETE /oauth2/register/{client_id} to authenticate the registrant.
--
-- token_endpoint_auth_method already exists from migration 003 (default 'none');
-- DCR-registered clients persist their declared method on registration.

ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS registration_source       VARCHAR(50) NOT NULL DEFAULT 'internal',
    ADD COLUMN IF NOT EXISTS registration_access_token VARCHAR(255);
