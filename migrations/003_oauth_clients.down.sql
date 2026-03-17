-- 003_oauth_clients.down.sql
-- Reverses 003_oauth_clients.up.sql
-- Drop oauth_tokens first (references oauth_clients.client_id)

DROP INDEX IF EXISTS idx_oauth_tokens_tenant;
DROP INDEX IF EXISTS idx_oauth_tokens_expires_at;
DROP INDEX IF EXISTS idx_oauth_tokens_client_id;
DROP INDEX IF EXISTS idx_oauth_tokens_jti;
DROP TABLE IF EXISTS oauth_tokens;

DROP INDEX IF EXISTS idx_oauth_clients_client_id;
DROP INDEX IF EXISTS idx_oauth_clients_tenant;
DROP TABLE IF EXISTS oauth_clients;
