-- 040_service_keys_fk_cascade.up.sql
-- Reconcile service_keys.identity_id FK to match migration 006's declared
-- ON DELETE CASCADE on legacy deployments where CREATE TABLE IF NOT EXISTS
-- was a no-op (the table predates the cascade and the constraint never got
-- re-applied). Fresh deployments are a no-op (constraint flip to identical
-- shape). See highflame-authn#109 / zeroid#187 for the user-visible incident
-- this drift originally produced, and zeroid#196 for the schema-drift root
-- cause this migration closes.

ALTER TABLE service_keys
    DROP CONSTRAINT IF EXISTS service_keys_identity_id_fkey;

ALTER TABLE service_keys
    ADD CONSTRAINT service_keys_identity_id_fkey
    FOREIGN KEY (identity_id) REFERENCES identities(id) ON DELETE CASCADE;
