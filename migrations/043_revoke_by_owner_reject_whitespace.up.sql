-- 043_revoke_by_owner_reject_whitespace.up.sql
-- Extend migration 042's empty-owner guard to whitespace: a whitespace-only or
-- padded p_owner_user_id passes 042's `= ''` check but matches NO stored row
-- (ownerless identities store exactly ''; VARCHAR equality is exact, no
-- CHAR-style pad semantics), so the cascade "succeeds" with zero revocations.
-- For the intended caller — the SCIM offboarding fan-out (INV-IDN-010 /
-- ADR 0028) — that is the worst failure mode: the worker records a successful
-- offboarding while the departing human's agents keep running with live
-- credentials. A malformed owner must fail loudly, not read as healthy.
--
-- Mirrors the trim-aware service guards (OffboardOwner,
-- RevokeAllActiveForOwner) in SQL so the guarantee survives a caller that goes
-- straight to the function. Same rationale as 042: defense in depth is cheap
-- and the failure mode is not recoverable.
--
-- Everything else — the recursive walk, CYCLE guard, depth cap 50, liveness
-- filters on the final UPDATE only, and the RETURNING projection — is carried
-- over from 042 verbatim. CREATE OR REPLACE keeps the signature stable, so no
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
    IF p_owner_user_id IS NULL OR btrim(p_owner_user_id) = '' OR p_owner_user_id <> btrim(p_owner_user_id) THEN
        RAISE EXCEPTION
            'revoke_credentials_by_owner: p_owner_user_id must be trimmed and non-empty (an empty owner matches every ownerless identity in the account; a padded one silently matches nothing)'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF p_account_id IS NULL OR btrim(p_account_id) = '' OR p_account_id <> btrim(p_account_id) THEN
        RAISE EXCEPTION
            'revoke_credentials_by_owner: p_account_id must be trimmed and non-empty (tenant scope is required)'
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
