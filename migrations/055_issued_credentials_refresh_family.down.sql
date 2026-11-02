-- 055_issued_credentials_refresh_family.down.sql
-- Reverses 055_issued_credentials_refresh_family.up.sql.
--
-- Roll the binary back FIRST. Bun enumerates model columns explicitly, so a
-- binary that knows about refresh_family_id writes it on every credential
-- insert; against a schema without the column every token issuance fails.
--
-- Dropping the column only loses the access-token-to-family link: a later
-- refresh-token reuse (or authorization-code replay) still revokes the
-- family's refresh tokens, but no longer reaches the access tokens minted from
-- it. Those stay valid until their own expiry.

SET LOCAL lock_timeout = '5s';

DROP INDEX IF EXISTS idx_issued_credentials_refresh_family_id;

ALTER TABLE issued_credentials DROP COLUMN IF EXISTS refresh_family_id;
