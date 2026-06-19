-- 033_refresh_tokens_expires_at_index.up.sql
-- Index refresh_tokens.expires_at to support the cleanup worker's expiry sweep.
--
-- Under refresh-token rotation every refresh inserts a successor row and
-- revokes its predecessor (RFC 6749 §6 / reuse detection). Nothing deleted
-- those rows, so the table grew one row per refresh forever. The cleanup
-- worker now deletes refresh_tokens whose expires_at is in the past (an
-- expired refresh token is unusable: every lookup requires expires_at > now).
-- That DELETE filters on expires_at, so without this index the sweep degrades
-- to a full table scan as the table grows — defeating the purpose.
--
-- Mirrors idx_issued_credentials_expires_at (migration 001), which backs the
-- analogous credential-expiry sweep.
--
-- Lock posture: plain CREATE INDEX (not CONCURRENTLY) because golang-migrate
-- wraps each migration in a transaction and CONCURRENTLY cannot run inside
-- one. The table is small relative to a hot OLTP table and this runs in the
-- migration window; if it ever needs to run online, pull this statement out
-- and rerun manually with CREATE INDEX CONCURRENTLY.

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at
    ON refresh_tokens (expires_at);
