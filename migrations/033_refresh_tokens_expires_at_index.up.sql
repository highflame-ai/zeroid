-- 033_refresh_tokens_expires_at_index.up.sql
-- Index refresh_tokens.expires_at to support the cleanup worker's expiry sweep.
--
-- Under refresh-token rotation every refresh inserts a successor row and
-- revokes its predecessor (RFC 6749 §6 / reuse detection). With no sweep the
-- table grew linearly with token traffic; the cleanup worker now deletes rows
-- whose expires_at is past the reuse-detection grace window. That DELETE
-- filters on expires_at, so without this index the sweep degrades to a full
-- table scan as the table grows — defeating the purpose.
--
-- Mirrors idx_issued_credentials_expires_at (migration 001), which backs the
-- analogous credential-expiry sweep.
--
-- Lock posture: plain CREATE INDEX takes a SHARE lock that blocks writes for
-- the build. The table is small relative to a hot OLTP table and this runs in
-- the migration window; if it ever needs to run online, switch to
-- CREATE INDEX CONCURRENTLY (which cannot run inside the migration transaction).

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at
    ON refresh_tokens (expires_at);
