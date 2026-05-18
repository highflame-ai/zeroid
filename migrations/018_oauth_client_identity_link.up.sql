-- 018_oauth_client_identity_link.up.sql
-- Adds optional identity_id to oauth_clients so an OAuth client can be
-- explicitly bound to an agent identity. When set, authorization_code and
-- refresh_token grants gate token issuance on the linked identity's
-- expires_at and status — same protection the api_key and jwt_bearer
-- paths already have.
--
-- Backward compatible: existing oauth_clients rows have identity_id =
-- NULL, which retains the pre-018 human-session behaviour (no identity
-- gate, sub = user_id, application_id = client_id). Deployers who want
-- the gate explicitly link a client to an identity at create or update.
--
-- The ON DELETE SET NULL clause mirrors api_keys: deleting an identity
-- nulls out the link but leaves the OAuth client intact so refresh
-- tokens already in flight don't disappear under callers — they'll just
-- fail the next exchange with "identity_expired" once the cascade has
-- run.

ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS identity_id UUID REFERENCES identities(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_oauth_clients_identity_id
    ON oauth_clients (identity_id)
    WHERE identity_id IS NOT NULL;
