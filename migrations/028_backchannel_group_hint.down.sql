-- 028_backchannel_group_hint.down.sql

ALTER TABLE backchannel_auth_requests
    DROP COLUMN IF EXISTS group_hint;
