-- 043_revoke_by_owner_reject_whitespace.down.sql
-- Restores the migration-042 function body (empty-only guard, no whitespace
-- check). Same signature and return type, so CREATE OR REPLACE suffices —
-- mirroring how 042's down restores the 041 body.
--
-- WARNING: rolling this back reintroduces the silent-no-op hole 043 closed —
-- a whitespace-only or padded p_owner_user_id again passes the guard, matches
-- no stored row, and reports success with zero revocations. The trim-aware
-- service-layer guards still apply to callers that go through them; this
-- rollback only removes the in-database backstop.

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
    IF p_owner_user_id IS NULL OR p_owner_user_id = '' THEN
        RAISE EXCEPTION
            'revoke_credentials_by_owner: p_owner_user_id must be non-empty (an empty owner matches every ownerless identity in the account)'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF p_account_id IS NULL OR p_account_id = '' THEN
        RAISE EXCEPTION
            'revoke_credentials_by_owner: p_account_id must be non-empty (tenant scope is required)'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

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
