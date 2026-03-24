-- 007_oauth_clients_is_mcp.up.sql
-- Adds is_mcp flag to oauth_clients so MCP vs CLI token behaviour (TTL, refresh
-- token issuance) is stored in the registry instead of server config.
--
-- Also adds redirect_uris which was missing from the initial schema but is
-- required for proper authorization_code grant validation.

ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS is_mcp BOOLEAN NOT NULL DEFAULT FALSE;
