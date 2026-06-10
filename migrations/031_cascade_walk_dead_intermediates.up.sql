-- 031_cascade_walk_dead_intermediates.up.sql
-- Fixes a reachability hole in the cascade-revocation functions (007/029):
-- the recursive traversal legs required every visited node to be live
-- (is_revoked = FALSE AND expires_at > p_revoked_at), so an expired or
-- already-revoked INTERMEDIATE credential stopped the walk and its still-live
-- descendants were never revoked.
--
-- Concrete failure: orchestrator token A delegates to child B late in A's
-- lifetime; A expires; A's identity is then revoked. The walk anchored on A
-- (or on the identity) finds A dead, never reaches B, and B stays valid for
-- its full remaining TTL despite its entire ancestry being revoked.
--
-- The fix moves the liveness filters out of the traversal: the chain CTE now
-- walks ALL parent_jti edges (cycle guard + depth cap unchanged), and the
-- final UPDATE alone decides which visited rows actually flip — only rows
-- that are not yet revoked and not yet expired. Returned-set semantics are
-- unchanged: callers still receive exactly the credentials that were live
-- and are now revoked, so the RevocationNotifier fan-out stays accurate and
-- already-dead rows generate no events.
--
-- The anchor legs likewise drop the liveness filters so a dead anchor's live
-- descendants are reachable (RFC 7009 revoke on an expired parent must still
-- kill the family).
--
-- Companion application-level changes (same release):
--   * token_exchange clamps child exp to the parent credential's expiry, so
--     dead-intermediate chains stop being produced going forward.
--   * the cleanup worker retains expired credential rows for a grace window
--     so parent_jti edges survive long enough for any late cascade to walk.
--
-- Return type is unchanged from 029, so CREATE OR REPLACE suffices.

CREATE OR REPLACE FUNCTION revoke_credentials_cascade(
    p_identity_id UUID,
    p_revoked_at  TIMESTAMPTZ,
    p_reason      TEXT
) RETURNS TABLE(
    jti         VARCHAR(255),
    identity_id UUID,
    account_id  VARCHAR(255),
    project_id  VARCHAR(255),
    expires_at  TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    WITH RECURSIVE chain(id, jti, depth) AS (
        SELECT ic.id, ic.jti, 0
        FROM issued_credentials ic
        WHERE ic.identity_id = p_identity_id
        UNION ALL
        SELECT ic.id, ic.jti, chain.depth + 1
        FROM issued_credentials ic
        JOIN chain ON ic.parent_jti = chain.jti
        WHERE chain.depth < 50
    )
    CYCLE jti SET is_cycle TO TRUE DEFAULT FALSE USING cycle_path
    , revoked AS (
        UPDATE issued_credentials ic
        SET is_revoked    = TRUE,
            revoked_at    = p_revoked_at,
            revoke_reason = p_reason
        WHERE ic.id IN (SELECT c.id FROM chain c WHERE NOT c.is_cycle)
          AND ic.is_revoked = FALSE
          AND ic.expires_at > p_revoked_at
        RETURNING ic.jti, ic.identity_id, ic.account_id, ic.project_id, ic.expires_at
    )
    SELECT r.jti, r.identity_id, r.account_id, r.project_id, r.expires_at
    FROM revoked r;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION revoke_credential_cascade(
    p_id         UUID,
    p_account_id TEXT,
    p_project_id TEXT,
    p_revoked_at TIMESTAMPTZ,
    p_reason     TEXT
) RETURNS TABLE(
    jti         VARCHAR(255),
    identity_id UUID,
    account_id  VARCHAR(255),
    project_id  VARCHAR(255),
    expires_at  TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    WITH RECURSIVE chain(id, jti, depth) AS (
        SELECT ic.id, ic.jti, 0
        FROM issued_credentials ic
        WHERE ic.id         = p_id
          AND ic.account_id = p_account_id
          AND ic.project_id = p_project_id
        UNION ALL
        SELECT ic.id, ic.jti, chain.depth + 1
        FROM issued_credentials ic
        JOIN chain ON ic.parent_jti = chain.jti
        WHERE chain.depth < 50
    )
    CYCLE jti SET is_cycle TO TRUE DEFAULT FALSE USING cycle_path
    , revoked AS (
        UPDATE issued_credentials ic
        SET is_revoked    = TRUE,
            revoked_at    = p_revoked_at,
            revoke_reason = p_reason
        WHERE ic.id IN (SELECT c.id FROM chain c WHERE NOT c.is_cycle)
          AND ic.is_revoked = FALSE
          AND ic.expires_at > p_revoked_at
        RETURNING ic.jti, ic.identity_id, ic.account_id, ic.project_id, ic.expires_at
    )
    SELECT r.jti, r.identity_id, r.account_id, r.project_id, r.expires_at
    FROM revoked r;
END;
$$ LANGUAGE plpgsql;
