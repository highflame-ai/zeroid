-- 003_oauth_clients.down.sql
-- Reverses 003_oauth_clients.up.sql

DROP INDEX IF EXISTS idx_oauth_clients_client_id;
DROP TABLE IF EXISTS oauth_clients;
