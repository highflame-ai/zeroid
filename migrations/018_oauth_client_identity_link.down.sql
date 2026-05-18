-- 018_oauth_client_identity_link.down.sql

DROP INDEX IF EXISTS idx_oauth_clients_identity_id;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS identity_id;
