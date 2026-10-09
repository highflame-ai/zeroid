-- Reverting 052. Roll the binary back first: bun enumerates model columns
-- explicitly, so a binary that knows these columns fails against a schema
-- without them.
SET LOCAL lock_timeout = '3s';

ALTER TABLE identities DROP COLUMN IF EXISTS public_key_channel_trusted;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS channel_trusted;
ALTER TABLE service_keys DROP COLUMN IF EXISTS channel_trusted;
