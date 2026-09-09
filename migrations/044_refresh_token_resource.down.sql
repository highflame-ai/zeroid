-- Reverting 044. READ THE ORDERING BELOW BEFORE RUNNING THIS.
--
-- ── Blast radius ────────────────────────────────────────────────────────────
--
-- Dropping this column while the CAP-IDN-027 binary is still deployed breaks
-- EVERY refresh-token operation, bound or not. Bun enumerates model columns
-- explicitly, so `refresh_tokens.resource` appears in the SELECT list of
-- GetByTokenHash and in every INSERT built from domain.RefreshToken — against a
-- schema without the column that is `ERROR: column rt.resource does not exist`
-- (SQLSTATE 42703). Consequences, which differ in how visible they are:
--
--   * the refresh_token grant fails outright on every request;
--   * the authorization_code grant degrades SILENTLY — the refresh-token error
--     is logged and an access token is returned with no refresh token, which
--     looks like a client bug for hours.
--
-- So this is NOT "ordinary unbound families are unaffected". They are affected
-- completely until the binary is also rolled back.
--
-- ── Ordering (all three steps, in this order) ───────────────────────────────
--
-- 1. REVOKE THE BOUND FAMILIES FIRST, while the column still exists:
--
--        UPDATE refresh_tokens
--           SET state = 'revoked', revoked_at = NOW()
--         WHERE resource IS NOT NULL AND state = 'active';
--
--    This step is not optional and cannot be deferred. After the DROP there is
--    no column left to select on, so the affected families become
--    unidentifiable — and the ceiling exists nowhere else to reconstruct from
--    (it was consented at authorize time and the code is long spent). Skip this
--    and up to 90 days of silently-widened families keep rotating: their
--    successors carry no `resource` claim, and INV-IDN-006 treats a token with
--    no claim as unbound and honours it at EVERY MCP server in the tenant.
--    That is fail-OPEN, the opposite of migration 039's down (whose successors
--    are merely rejected by the daemon).
--
--    idx_refresh_tokens_resource_bound exists to make this query cheap; without
--    it this is a sequential scan on a hot table in the emergency path.
--
-- 2. Roll the binary back to a pre-CAP-IDN-027 release.
--
-- 3. Then run this migration.
--
-- ── Untested path ──────────────────────────────────────────────────────────
--
-- No test in this repo executes any down migration, and neither does CI. This
-- one has never run anywhere. Rehearse it on stage1 — including the binary
-- rollback in step 2 — before relying on it in prod.

SET LOCAL lock_timeout = '3s';

ALTER TABLE refresh_tokens DROP CONSTRAINT IF EXISTS refresh_tokens_resource_nonempty;

DROP INDEX IF EXISTS idx_refresh_tokens_resource_bound;

ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS resource;
