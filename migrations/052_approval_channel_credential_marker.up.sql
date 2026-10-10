-- 052_approval_channel_credential_marker.up.sql
-- Records, per credential, whether it was written by a caller marked with
-- WithTrustedApprovalChannelWrite. The ciba:approve scope is issued only from
-- a credential that carries the mark:
--
--   service_keys.channel_trusted              the API key
--   oauth_clients.channel_trusted             the OAuth client (client_credentials)
--   identities.public_key_channel_trusted     the identity's public_key_pem
--                                             (jwt-bearer); rewritten on every
--                                             public key write
--
-- Constant defaults keep each ADD COLUMN metadata-only; existing credentials
-- read as unmarked.
SET LOCAL lock_timeout = '3s';

ALTER TABLE service_keys
    ADD COLUMN IF NOT EXISTS channel_trusted BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS channel_trusted BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE identities
    ADD COLUMN IF NOT EXISTS public_key_channel_trusted BOOLEAN NOT NULL DEFAULT false;
