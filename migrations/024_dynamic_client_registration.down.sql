-- IRREVERSIBLE FOR DCR-REGISTERED CLIENTS: dropping registration_access_token
-- destroys the bcrypt-hashed management bearers. After this down + a future
-- re-apply of the up, RFC 7592 GET/PUT/DELETE against any pre-existing
-- dynamic client will fail because the stored hash is gone. Dropping
-- registration_source also erases the trust boundary between admin- and
-- self-registered clients (all look 'internal' again). Treat this down
-- migration as emergency-only.

SET LOCAL lock_timeout = '3s';

ALTER TABLE oauth_clients
    DROP COLUMN IF EXISTS registration_access_token,
    DROP COLUMN IF EXISTS registration_source;
