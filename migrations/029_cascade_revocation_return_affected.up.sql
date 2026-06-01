-- 029_cascade_revocation_return_affected.up.sql
-- Evolves the two cascade-revocation functions (migration 007) from
-- RETURNS INTEGER (row count only) to RETURNS TABLE(...) so the application
-- can observe EXACTLY which credentials were revoked in a single statement —
-- without a fragile follow-up "SELECT ... WHERE revoked_at = $now" query.
--
-- This unblocks the RevocationNotifier hook: the
-- service layer fans out one revocation event per affected JTI to the
-- embedding application, which needs each revoked credential's jti, tenant,
-- expiry, and reason. Returning the affected rows directly keeps that
-- enumeration atomic with the cascade and avoids any timestamp-matching race.
--
-- Changing a function's return type is not an in-place CREATE OR REPLACE in
-- Postgres, so we DROP then recreate. The cascade logic (recursive parent_jti
-- walk, CYCLE guard, depth cap, tenant guards) is unchanged from migration 007
-- — only the RETURNING surface is added.
--
-- The caller computes the row count as the cardinality of the returned set,
-- so no separate count is needed.

DROP FUNCTION IF EXISTS revoke_credentials_cascade(UUID, TIMESTAMPTZ, TEXT);
DROP FUNCTION IF EXISTS revoke_credential_cascade(UUID, TEXT, TEXT, TIMESTAMPTZ, TEXT);

-- Identity-anchored cascade (CAE signal revocation + identity deactivation).
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
          AND ic.is_revoked  = FALSE
          AND ic.expires_at  > p_revoked_at
        UNION ALL
        SELECT ic.id, ic.jti, chain.depth + 1
        FROM issued_credentials ic
        JOIN chain ON ic.parent_jti = chain.jti
        WHERE ic.is_revoked = FALSE
          AND ic.expires_at > p_revoked_at
          AND chain.depth   < 50
    )
    CYCLE jti SET is_cycle TO TRUE DEFAULT FALSE USING cycle_path
    , revoked AS (
        UPDATE issued_credentials ic
        SET is_revoked    = TRUE,
            revoked_at    = p_revoked_at,
            revoke_reason = p_reason
        WHERE ic.id IN (SELECT c.id FROM chain c WHERE NOT c.is_cycle)
          AND ic.is_revoked = FALSE
        RETURNING ic.jti, ic.identity_id, ic.account_id, ic.project_id, ic.expires_at
    )
    SELECT r.jti, r.identity_id, r.account_id, r.project_id, r.expires_at
    FROM revoked r;
END;
$$ LANGUAGE plpgsql;

-- Single-credential-anchored cascade (RFC 7009 revoke + rotation + auth-code replay).
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
          AND ic.is_revoked = FALSE
          AND ic.expires_at > p_revoked_at
        UNION ALL
        SELECT ic.id, ic.jti, chain.depth + 1
        FROM issued_credentials ic
        JOIN chain ON ic.parent_jti = chain.jti
        WHERE ic.is_revoked = FALSE
          AND ic.expires_at > p_revoked_at
          AND chain.depth   < 50
    )
    CYCLE jti SET is_cycle TO TRUE DEFAULT FALSE USING cycle_path
    , revoked AS (
        UPDATE issued_credentials ic
        SET is_revoked    = TRUE,
            revoked_at    = p_revoked_at,
            revoke_reason = p_reason
        WHERE ic.id IN (SELECT c.id FROM chain c WHERE NOT c.is_cycle)
          AND ic.is_revoked = FALSE
        RETURNING ic.jti, ic.identity_id, ic.account_id, ic.project_id, ic.expires_at
    )
    SELECT r.jti, r.identity_id, r.account_id, r.project_id, r.expires_at
    FROM revoked r;
END;
$$ LANGUAGE plpgsql;
