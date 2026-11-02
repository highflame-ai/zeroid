-- 042_revoke_by_owner_reject_empty.up.sql
-- Guard revoke_credentials_by_owner (migration 041) against an empty owner.
--
-- identities.owner_user_id is VARCHAR(255) NOT NULL (001_init_schema), so an
-- ownerless identity does not store NULL — it stores ''. Ownerless is a real,
-- documented posture, not an anomaly: discovered identities are created without
-- an owner on purpose (identity-lifecycle.md "Ownership: relaxed for discovered
-- only"), and internal/store/postgres/identity.go queries them with an explicit
-- (owner_user_id IS NULL OR owner_user_id = '') facet.
--
-- 041's seed predicate is a plain equality:
--
--     WHERE i.owner_user_id = p_owner_user_id
--       AND i.account_id    = p_account_id
--
-- so calling it with p_owner_user_id = '' selects EVERY ownerless identity in
-- the account and cascade-revokes each one's entire delegation subtree. The
-- realistic trigger is the intended caller — an IdP offboarding webhook whose
-- user-id field arrives blank — turning "revoke one departing human's agents"
-- into a tenant-wide outage of the workloads least likely to be monitored.
-- Revoked credentials cannot be un-revoked.
--
-- internal/service/credential.go rejects the empty owner before reaching the
-- repo. This mirrors it in SQL so the guarantee survives a caller that goes
-- straight to the function — a direct psql session, another service, or a repo
-- method added later. Defense in depth is cheap here and the failure mode is
-- not recoverable.
--
-- RAISE EXCEPTION rather than returning zero rows: a blank owner is a caller
-- bug, and silently succeeding with "revoked 0 credentials" would let a broken
-- offboarding integration look healthy indefinitely. Failing loudly surfaces it
-- on the first malformed event.
--
-- Everything else — the recursive walk, CYCLE guard, depth cap 50, liveness
-- filters on the final UPDATE only, and the RETURNING projection — is carried
-- over from 041 verbatim. CREATE OR REPLACE keeps the signature stable, so no
-- caller changes.

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
