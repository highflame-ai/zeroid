-- 064_backchannel_requesting_groups.up.sql
-- Carry the requesting token's groups on a CIBA request.
--
-- A bc-authorize request with a requesting_token mints, on approval, a token
-- that keeps the requesting chain's subject and actors. Its person's groups
-- (the `groups` claim the person grants copy from the IdP) must carry over
-- too, or the continuation token would silently lose them. Copied from the
-- verified requesting token when the request is created.
--
-- Nullable, no default, no backfill: NULL means the requesting token had no
-- groups (or the row predates this migration), and the minted token carries
-- none, as before. Metadata-only ALTER on PG 11+; lock_timeout bounds the wait
-- for the ACCESS EXCLUSIVE lock behind in-flight transactions.
SET LOCAL lock_timeout = '3s';

ALTER TABLE backchannel_auth_requests
    ADD COLUMN IF NOT EXISTS requesting_groups TEXT[];
