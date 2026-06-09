-- 032_refresh_tokens_expires_at_index.down.sql
-- Reverses 032: drops the refresh_tokens expiry index. The cleanup worker's
-- sweep still functions without it (it just falls back to a sequential scan).

DROP INDEX IF EXISTS idx_refresh_tokens_expires_at;
