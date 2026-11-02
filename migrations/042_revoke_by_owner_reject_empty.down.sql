-- 042_revoke_by_owner_reject_empty.down.sql
-- Restores the migration-041 function body (no empty-owner guard). Same
-- signature and return type, so CREATE OR REPLACE suffices — mirroring how
-- 031's down restores the 029 bodies.
--
-- WARNING: rolling this back reintroduces the hole 042 closed — calling
-- revoke_credentials_by_owner with an empty p_owner_user_id again matches every
-- ownerless identity in the account (owner_user_id is NOT NULL, so ownerless
-- rows store '') and cascade-revokes each one's whole delegation subtree.
-- Revoked credentials cannot be un-revoked. The service-layer guard in
-- internal/service/credential.go still applies to callers that go through it;
-- this rollback only removes the in-database backstop.

CREATE OR REPLACE FUNCTION revoke_credentials_by_owner(
    p_owner_user_id TEXT,
    p_account_id    TEXT,
    p_revoked_at    TIMESTAMPTZ,
    p_reason        TEXT
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
        JOIN identities i ON i.id = ic.identity_id
        WHERE i.owner_user_id = p_owner_user_id
          AND i.account_id    = p_account_id
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
