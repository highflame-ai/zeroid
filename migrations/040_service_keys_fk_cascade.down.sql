-- 040_service_keys_fk_cascade.down.sql
-- Reverses 040_service_keys_fk_cascade.up.sql
-- Flips the FK back to ON DELETE NO ACTION (the implicit default when no
-- ON DELETE clause is specified — the presumed pre-migration-006 legacy
-- shape). Verify against a dev1 snapshot before relying on this in a real
-- rollback; if the legacy constraint turns out to have had a different
-- ON DELETE behaviour, update this file to match before use.

ALTER TABLE service_keys
    DROP CONSTRAINT IF EXISTS service_keys_identity_id_fkey;

ALTER TABLE service_keys
    ADD CONSTRAINT service_keys_identity_id_fkey
    FOREIGN KEY (identity_id) REFERENCES identities(id) ON DELETE NO ACTION;
