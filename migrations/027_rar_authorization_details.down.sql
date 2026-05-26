-- 027_rar_authorization_details.down.sql

ALTER TABLE backchannel_auth_requests
    DROP COLUMN IF EXISTS authorization_details;
