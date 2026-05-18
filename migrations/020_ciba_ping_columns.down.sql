-- 020_ciba_ping_columns.down.sql
ALTER TABLE backchannel_auth_requests DROP COLUMN IF EXISTS client_notification_token;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS client_notification_endpoint;
