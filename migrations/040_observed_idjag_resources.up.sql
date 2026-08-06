-- 040_observed_idjag_resources.up.sql
-- Observed MCP servers, learned from ID-JAG redemptions (zeroid#259).
--
-- Every successful ID-JAG exchange carries an RFC 8707 `resource` claim naming
-- the MCP server the corporate IdP authorized, and we mint a token
-- audience-restricted to exactly that value (ADR 0010 D4). Until now we parsed
-- it, used it, and discarded it — so the one authoritative record of which MCP
-- servers an organization's agents actually reach existed only in flight.
--
-- Recording it turns a byproduct of the mint into an MCP inventory that, unlike
-- name heuristics or public-registry matching, sees an enterprise's PRIVATE
-- servers, and unlike an RFC 9728 probe needs no outbound request. It is also
-- evidence of use rather than intent: a configured-but-never-called resource
-- never appears here, a live one does.
--
-- observed_idjag_resources: one row per (tenant, resource) — NOT per exchange.
--   Resources are a small, slow-moving set (one per MCP endpoint), so this is an
--   upsert-and-bump-last_seen table, not a log. A busy tenant redeeming
--   thousands of ID-JAGs a day against three MCP servers holds three rows.
--
--   authorizing_iss is the upstream IdP that vouched for the resource — the same
--   value propagated into the token as user_id_iss — so a resource can be
--   attributed to the issuer that authorized it, which is what lets a consumer
--   join this against a discovery connector for the same IdP.
--
--   Written on the SUCCESSFUL-exchange path only. A rejected exchange must never
--   create a row, or anyone able to reach /oauth2/token could plant entries into
--   a tenant's inventory.
--
-- Storage: unlike id_jag_jti this is low-churn and long-lived (UPDATEs to
-- last_seen_at dominate, INSERTs are rare), so the aggressive autovacuum tuning
-- there is inappropriate here. fillfactor=85 leaves page headroom for the
-- repeated HOT updates to last_seen_at.
--
-- Lock posture: CREATE TABLE / CREATE INDEX on a brand-new empty table, so no
-- concurrent-rebuild concern. lock_timeout scopes any blocking-acquire.

SET LOCAL lock_timeout = '3s';

CREATE TABLE IF NOT EXISTS observed_idjag_resources (
    account_id      VARCHAR(255) NOT NULL,
    project_id      VARCHAR(255) NOT NULL,
    -- The RFC 8707 resource URI, normalized (see NormalizeResource in the store).
    resource        VARCHAR(2048) NOT NULL,
    -- Upstream IdP `iss` that authorized this resource.
    authorizing_iss VARCHAR(2048) NOT NULL,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (account_id, project_id, resource)
) WITH (fillfactor = 85);

-- The read path is always "every resource for this tenant, most recent first".
CREATE INDEX IF NOT EXISTS idx_observed_idjag_resources_tenant_last_seen
    ON observed_idjag_resources (account_id, project_id, last_seen_at DESC);
