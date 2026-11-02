-- 061_oauth_client_identity_cascade.up.sql
-- Deleting an identity now deletes the OAuth clients linked to it.
--
-- 018 used ON DELETE SET NULL, which turned a linked client into an unlinked
-- one. The tenant-scope rule on the OAuth client admin routes treats an
-- unlinked client as global, so after the identity was gone any tenant could
-- get, rotate the secret of, or delete a client that belonged to the identity's
-- tenant. Refresh tokens did not fail with identity_expired either: with no
-- link the refresh grant skips the identity gate.
--
-- Soft deletes (DeactivateIdentity) keep the row and the link, so they are not
-- affected. This only changes the hard delete.

ALTER TABLE oauth_clients
    DROP CONSTRAINT IF EXISTS oauth_clients_identity_id_fkey;

ALTER TABLE oauth_clients
    ADD CONSTRAINT oauth_clients_identity_id_fkey
    FOREIGN KEY (identity_id) REFERENCES identities(id) ON DELETE CASCADE;
