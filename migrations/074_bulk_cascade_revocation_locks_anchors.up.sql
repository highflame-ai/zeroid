-- 074_bulk_cascade_revocation_locks_anchors.up.sql
-- The bulk cascades, revoke_credentials_cascade (every token of an identity:
-- deactivation, CAE signals) and revoke_credentials_by_owner (every token of
-- an owner's identities: offboarding), now lock the tokens they start from
-- before they walk, as revoke_credential_cascade does since 073.
--
-- A delegated issuance locks its new token's parent and every token above it
-- FOR SHARE, root first (CredentialRepository.Create). The bulk UPDATE locks
-- the rows it revokes in whatever order its plan reads them, so it could take
-- a token below the root before the root. An issuance holding the root and
-- waiting for that token, and the cascade waiting for the root, deadlocked:
-- PostgreSQL aborted one, failing the exchange with a 500 or the revocation
-- itself. And when the issuance locked first and the cascade waited for it,
-- the walk ran on the snapshot it took before the wait, missed the new token,
-- and left it live below a revoked root, with no revocation event.
--
-- Every token the walk reaches is an anchor or below one, so every issuance
-- below the walk holds a share lock on an anchor. Locking the anchors first,
-- in a statement of their own, serializes the two as 073 does for one token:
-- the cascade either waits for the issuance to commit, and the walk, a later
-- statement with a new snapshot, finds its token; or the issuance waits, and
-- then finds its anchor revoked and is refused. The anchors are locked
-- parents first (delegation_depth never falls down a chain, and a token is
-- issued after its parent), so the cascade never holds a token below one an
-- issuance holds while waiting for it.
--
-- Revoked anchors are not locked: an issuance below one is refused whatever
-- the cascade does. Expired, unrevoked ones are, since the walk passes
-- through them (031).
--
-- No planner settings: 060 leaves the bulk cascades to the planner, and
-- TestCascadeFunctionsPinIndexWalk checks it. Everything else is carried over
-- from 031 (identity) and 043 (owner) verbatim. Return types are unchanged,
-- so CREATE OR REPLACE suffices.

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
    PERFORM 1
    FROM issued_credentials ic
    WHERE ic.identity_id = p_identity_id
      AND ic.is_revoked = FALSE
    ORDER BY ic.delegation_depth, ic.issued_at, ic.id
    FOR NO KEY UPDATE;

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
    IF p_owner_user_id IS NULL
       OR btrim(p_owner_user_id, E' \t\n\r\f\v') = ''
       OR p_owner_user_id <> btrim(p_owner_user_id, E' \t\n\r\f\v') THEN
        RAISE EXCEPTION
            'revoke_credentials_by_owner: p_owner_user_id must be trimmed and non-empty (an empty owner matches every ownerless identity in the account; a padded one silently matches nothing)'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF p_account_id IS NULL
       OR btrim(p_account_id, E' \t\n\r\f\v') = ''
       OR p_account_id <> btrim(p_account_id, E' \t\n\r\f\v') THEN
        RAISE EXCEPTION
            'revoke_credentials_by_owner: p_account_id must be trimmed and non-empty (tenant scope is required)'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    PERFORM 1
    FROM issued_credentials ic
    JOIN identities i ON i.id = ic.identity_id
    WHERE i.owner_user_id = p_owner_user_id
      AND i.account_id    = p_account_id
      AND ic.is_revoked   = FALSE
    ORDER BY ic.delegation_depth, ic.issued_at, ic.id
    FOR NO KEY UPDATE OF ic;

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
