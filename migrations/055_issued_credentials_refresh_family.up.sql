-- 055_issued_credentials_refresh_family.up.sql
-- Record which refresh-token family an access token was issued under, so the
-- access tokens can be revoked together with the family.
--
-- refresh_tokens already carries family_id (migration 001): every rotation
-- copies it onto the successor row, and refresh-token reuse detection revokes
-- the family's refresh tokens by it. What was missing is the link from an
-- ACCESS token back to that family. Without it, revoking a family stopped the
-- next rotation but left every access token minted from the family valid until
-- its own expiry — both the token from the original authorization_code
-- exchange and each token minted by a refresh.
--
-- RFC 9700 §4.14.2: when an invalidated refresh token is presented, the
-- authorization server revokes the active refresh token. RFC 6749 §4.1.2: on
-- authorization-code replay the server SHOULD revoke all tokens previously
-- issued based on that code. Both now reach the access tokens through this
-- column.
--
-- Nullable, no default, no backfill. NULL ⇒ the credential was not issued
-- under a refresh family: every grant other than authorization_code (when a
-- refresh token is issued alongside), refresh_token, and the external-principal
-- exchange with a refresh token — and every row written before this migration.
-- Pre-migration access tokens age out on their own TTL; the refresh tokens of
-- their families are still revoked by family_id as before.
--
-- UUID to match refresh_tokens.family_id. Not a foreign key: refresh-token rows
-- are deleted by the cleanup worker on their own clock, and an access token's
-- audit row (audit_retention_until, migration 037) outlives them by design.
--
-- Partial index for the only query shape, `WHERE refresh_family_id = ?`,
-- mirroring idx_issued_credentials_mission_id (migration 022).
--
-- LOCK POSTURE (cf. migrations 022/037): the ALTER is metadata-only on PG 11+
-- (nullable, no default — no rewrite). The CREATE INDEX is non-CONCURRENT and
-- runs in the same implicit transaction, so it holds a write-blocking lock on
-- issued_credentials for the duration of one scan of the table. Every existing
-- row has a NULL in the new column, so the index itself is empty, but the scan
-- is not free on a large table. If that matters for an installation, apply the
-- ALTER here and build the index out of band with CREATE INDEX CONCURRENTLY
-- (which cannot run inside this file's transaction). lock_timeout fails fast
-- rather than queueing the token endpoint behind a long-running transaction.
SET LOCAL lock_timeout = '5s';

ALTER TABLE issued_credentials
    ADD COLUMN IF NOT EXISTS refresh_family_id UUID;

CREATE INDEX IF NOT EXISTS idx_issued_credentials_refresh_family_id
    ON issued_credentials (refresh_family_id)
    WHERE refresh_family_id IS NOT NULL;
