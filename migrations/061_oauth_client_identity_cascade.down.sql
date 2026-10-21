-- 061_oauth_client_identity_cascade.down.sql

ALTER TABLE oauth_clients
    DROP CONSTRAINT IF EXISTS oauth_clients_identity_id_fkey;

ALTER TABLE oauth_clients
    ADD CONSTRAINT oauth_clients_identity_id_fkey
    FOREIGN KEY (identity_id) REFERENCES identities(id) ON DELETE SET NULL;
