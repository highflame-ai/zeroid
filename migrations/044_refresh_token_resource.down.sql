-- Dropping resource removes the RFC 8707 ceiling from every active
-- refresh-token family. After down + re-apply, rotating a resource-bound
-- refresh token issues a successor access token with NO `resource` claim — so
-- INV-IDN-006 stops recognising it as bound and Shield honours it at every MCP
-- server in the tenant. Ordinary (unbound) refresh families are unaffected.
--
-- That is a widening, not a breakage, which is the opposite of migration 039's
-- down (there the successor is REJECTED by the daemon; here it is accepted too
-- broadly). Worth being explicit about: rolling this back is fail-OPEN for
-- already-issued families, so the rollback plan for a bad deploy is to revoke
-- the affected refresh families rather than to rely on the down alone.
--
-- The data loss is the ceiling itself, which cannot be reconstructed — it was
-- consented at authorize time and exists nowhere else once the code is spent.

SET LOCAL lock_timeout = '3s';

ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS resource;
