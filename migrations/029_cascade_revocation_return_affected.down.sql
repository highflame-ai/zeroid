-- 029_cascade_revocation_return_affected.down.sql
-- Reverses 029, restoring the RETURNS INTEGER signatures from migration 007.

DROP FUNCTION IF EXISTS revoke_credentials_cascade(UUID, TIMESTAMPTZ, TEXT);
DROP FUNCTION IF EXISTS revoke_credential_cascade(UUID, TEXT, TEXT, TIMESTAMPTZ, TEXT);

CREATE OR REPLACE FUNCTION revoke_credentials_cascade(
    p_identity_id UUID,
    p_revoked_at TIMESTAMPTZ,
    p_reason      TEXT
) RETURNS INTEGER AS $$
DECLARE
    v_count INTEGER;
BEGIN
    WITH RECURSIVE chain(id, jti, depth) AS (
        SELECT id, jti, 0
        FROM issued_credentials
        WHERE identity_id = p_identity_id
          AND is_revoked  = FALSE
          AND expires_at  > p_revoked_at
        UNION ALL
        SELECT ic.id, ic.jti, chain.depth + 1
        FROM issued_credentials ic
        JOIN chain ON ic.parent_jti = chain.jti
        WHERE ic.is_revoked = FALSE
          AND ic.expires_at > p_revoked_at
          AND chain.depth   < 50
    )
    CYCLE jti SET is_cycle TO TRUE DEFAULT FALSE USING cycle_path
    UPDATE issued_credentials
    SET is_revoked    = TRUE,
        revoked_at    = p_revoked_at,
        revoke_reason = p_reason
    WHERE id IN (SELECT id FROM chain WHERE NOT is_cycle)
      AND is_revoked = FALSE;

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION revoke_credential_cascade(
    p_id         UUID,
    p_account_id TEXT,
    p_project_id TEXT,
    p_revoked_at TIMESTAMPTZ,
    p_reason     TEXT
) RETURNS INTEGER AS $$
DECLARE
    v_count INTEGER;
BEGIN
    WITH RECURSIVE chain(id, jti, depth) AS (
        SELECT id, jti, 0
        FROM issued_credentials
        WHERE id         = p_id
          AND account_id = p_account_id
          AND project_id = p_project_id
          AND is_revoked = FALSE
          AND expires_at > p_revoked_at
        UNION ALL
        SELECT ic.id, ic.jti, chain.depth + 1
        FROM issued_credentials ic
        JOIN chain ON ic.parent_jti = chain.jti
        WHERE ic.is_revoked = FALSE
          AND ic.expires_at > p_revoked_at
          AND chain.depth   < 50
    )
    CYCLE jti SET is_cycle TO TRUE DEFAULT FALSE USING cycle_path
    UPDATE issued_credentials
    SET is_revoked    = TRUE,
        revoked_at    = p_revoked_at,
        revoke_reason = p_reason
    WHERE id IN (SELECT id FROM chain WHERE NOT is_cycle)
      AND is_revoked = FALSE;

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$ LANGUAGE plpgsql;
