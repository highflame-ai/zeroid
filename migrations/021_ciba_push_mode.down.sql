-- 021_ciba_push_mode.down.sql
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS backchannel_token_delivery_mode;
