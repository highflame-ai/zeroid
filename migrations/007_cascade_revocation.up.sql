-- 007_cascade_revocation.up.sql
-- Adds a stored function that atomically revokes all active credentials for an
-- identity and cascades the revocation to every downstream delegated credential
-- in the parent_jti chain (RFC 8693 token_exchange descendants), regardless of
-- which identity issued those child tokens.
--
-- Two independent cycle-safety mechanisms are used:
--   1. The SQL-standard CYCLE clause (Postgres 14+) detects revisited jti values.
--   2. A hard depth cap halts traversal even if the CYCLE clause were bypassed.
--
-- Returns the total number of rows marked revoked (root credentials + descendants).

CREATE OR REPLACE FUNCTION revoke_credentials_cascade(
    p_identity_id UUID,
    p_revoked_at TIMESTAMPTZ,
    p_reason      TEXT
) RETURNS INTEGER AS $$
DECLARE
    v_count INTEGER;
BEGIN
    -- Anchor: all active credentials owned directly by this identity.
    --
    -- Recursive leg: follows parent_jti links to child credentials issued via
    -- token_exchange. Children may belong to different identities (sub-agents),
    -- so we cannot filter by identity_id there. Cross-tenant traversal is
    -- prevented structurally because parent_jti links are established at
    -- issuance time within a single tenant-scoped token-exchange request,
    -- and all JTIs are UUIDs with negligible collision probability.
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

-- Adds a stored function that atomically revokes a single credential and cascades
-- the revocation to every downstream delegated credential in the parent_jti chain
-- (RFC 8693 token_exchange descendants).
--
-- Used by the per-token revocation path (POST /oauth2/token/revoke and credential
-- rotation). Complements revoke_credentials_cascade above which is anchored on
-- identity_id for CAE signal-triggered revocation.
--
-- account_id and project_id are required on the anchor as tenant-safety guards:
-- they ensure a caller cannot revoke a credential outside their tenant even if
-- they obtain another tenant's credential UUID.
--
-- revoked_at is supplied by the caller so the application clock is the authoritative
-- timestamp recorded on every row in the cascade, ensuring consistency across rows.
--
-- Returns the total number of rows marked revoked (the token itself + descendants).

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
