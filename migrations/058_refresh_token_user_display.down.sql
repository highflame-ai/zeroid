-- 058_refresh_token_user_display.down.sql
-- Roll the binary back first: a server running the up migration's code
-- writes and reads these columns on every authorization_code and refresh
-- grant.
SET LOCAL lock_timeout = '5s';

ALTER TABLE refresh_tokens
    DROP COLUMN IF EXISTS user_name,
    DROP COLUMN IF EXISTS user_email;
