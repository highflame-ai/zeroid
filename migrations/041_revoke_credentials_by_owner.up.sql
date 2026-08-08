-- 041_revoke_credentials_by_owner.up.sql
-- Owner-scoped cascade revocation: revoke every active credential belonging to
-- an identity owned by a given human (identities.owner_user_id) within one
-- account, plus every delegated descendant reachable through the parent_jti
-- chain.
--
-- This is the missing primitive for human offboarding: when a person is
-- deactivated in the IdP, an offboarding handler can revoke every agent that
-- person owns — and every sub-agent those agents delegated to — in one atomic
-- statement, instead of the tokens surviving until their natural TTL.
--
-- Scoped by (owner_user_id, account_id) for tenant safety: a deactivation event
-- carries the account context, and this never reaches across accounts even if
-- the same owner id somehow appeared elsewhere.
--
-- Traversal/return semantics mirror revoke_credentials_cascade (migration 031):
-- the recursive walk crosses dead intermediates (no liveness filter in the
-- traversal), the final UPDATE alone decides which visited rows flip (only
-- not-yet-revoked, not-yet-expired), and the returned set is exactly the rows
-- that were live and are now revoked — so the RevocationNotifier fan-out stays
-- accurate and already-dead rows emit no events. Cycle guard + depth cap 50
-- match the identity/credential cascades.

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
