ALTER TABLE oauth_clients
    DROP COLUMN IF EXISTS registration_access_token,
    DROP COLUMN IF EXISTS registration_source;
