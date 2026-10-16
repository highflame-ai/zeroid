-- GetByWIMSEURI (every jwt_bearer grant, token_exchange actor resolution and
-- /identities/by-wimse) filters identities on wimse_uri, which has had no
-- index since 001. The planner fell back to idx_identities_tenant or a seq
-- scan, so lookup cost grew with the tenant's identity count: at 1M
-- identities one jwt_bearer grant spent 1.25 s scanning, capping the token
-- endpoint near 25/s.
--
-- wimse_uri embeds account and project, so it is selective on its own.
--
-- LOCK POSTURE (cf. 017/055): non-CONCURRENT inside golang-migrate's
-- transaction, so writes to identities block for one scan of the table.
-- Large installations can pre-build it out of band with
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_identities_wimse_uri ON identities (wimse_uri);
-- and this migration becomes a no-op.
SET LOCAL lock_timeout = '5s';

CREATE INDEX IF NOT EXISTS idx_identities_wimse_uri ON identities (wimse_uri);
