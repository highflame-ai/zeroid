-- 007_oauth_clients_is_mcp.down.sql
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS is_mcp;
