-- 073_cascade_revocation_locks_anchor.up.sql
-- revoke_credential_cascade (RFC 7009 revoke of one token) now locks the
-- token it revokes, and the live tokens delegated from it, before the walk
-- that revokes them.
--
-- Before, a token exchange could store a child of a token while that token's
-- revocation was running. The exchange checked that its subject_token was
-- active, the cascade then revoked the subject and walked its descendants,
-- and only after that did the exchange INSERT the child: unrevoked, below a
-- revoked parent, and valid for its whole TTL. Revoking the parent again did
-- not reach it either (the RFC 7009 handler skipped an already-revoked token).
--
-- The fix has two halves, and this is the revocation's half:
--
--   * Issuance (CredentialRepository.Create) locks the new credential's
--     parent and every credential above it FOR SHARE, root first, in the
--     INSERT's transaction, and refuses the INSERT if any of them is revoked.
--   * Revocation locks the anchor FOR NO KEY UPDATE, the lock its own UPDATE
--     takes anyway, in a statement of its own, before the walk that revokes.
--
-- The anchor is an ancestor of every token the walk can reach, so an
-- issuance anywhere below it holds a share lock on it. Either the revocation
-- locks the anchor first, and the issuance waits for the revocation to commit
-- and then sees the anchor revoked; or the issuance locks first, and the
-- revocation waits for the INSERT to commit. The walk that revokes is a later
-- statement in a VOLATILE function, so under READ COMMITTED it takes a new
-- snapshot after the lock is granted and finds the new child.
--
-- The anchor lock does not filter on is_revoked or expires_at: revoking an
-- already revoked or expired token must still serialize with issuance below
-- it, so that a second revocation can sweep a descendant the old code left
-- live.
--
-- The first statement locks the live tokens below the anchor too, in the
-- same statement and in one order: delegation_depth, issued_at, id, which
-- puts a parent before its child (074 uses the same order). Every cascade
-- (this one and 074's) takes every lock it needs in that order, in its first
-- statement, so two cascades over overlapping trees take their shared tokens
-- in the same order and cannot deadlock. Locking the anchor alone first
-- could: a chain that comes back to the identity it started from (R of X →
-- M of Y → K of X) had X's cascade holding K, its own token, while this
-- cascade, revoking M, held M and walked down to K, and X's walk wanted M.
--
-- The second statement walks again, on its new snapshot, locks the live
-- tokens it reached in the same order (all of them already held, except a
-- child stored while the first statement waited), and updates them.
--
-- The SET clauses from 060 are carried forward: CREATE OR REPLACE FUNCTION
-- replaces the function's settings with the ones it names, and
-- TestCascadeFunctionsPinIndexWalk fails if they are dropped. Both walks keep
-- the depth bound of 50 (MaxLineageDepth).
--
-- Return type is unchanged from 029, so CREATE OR REPLACE suffices.

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
)
SET enable_hashjoin = off
SET enable_mergejoin = off
AS $$
BEGIN
    PERFORM 1
    FROM issued_credentials ic
    WHERE ic.id IN (
        WITH RECURSIVE chain(id, jti, depth) AS (
            SELECT a.id, a.jti, 0
            FROM issued_credentials a
            WHERE a.id         = p_id
              AND a.account_id = p_account_id
              AND a.project_id = p_project_id
            UNION ALL
            SELECT d.id, d.jti, chain.depth + 1
            FROM issued_credentials d
            JOIN chain ON d.parent_jti = chain.jti
            WHERE chain.depth < 50
        )
        CYCLE jti SET is_cycle TO TRUE DEFAULT FALSE USING cycle_path
        SELECT chain.id FROM chain WHERE NOT chain.is_cycle
    )
      AND (ic.id = p_id OR (ic.is_revoked = FALSE AND ic.expires_at > p_revoked_at))
    ORDER BY ic.delegation_depth, ic.issued_at, ic.id
    FOR NO KEY UPDATE OF ic;

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
    , locked AS (
        SELECT ic.id
        FROM issued_credentials ic
        WHERE ic.id IN (SELECT c.id FROM chain c WHERE NOT c.is_cycle)
          AND ic.is_revoked = FALSE
          AND ic.expires_at > p_revoked_at
        ORDER BY ic.delegation_depth, ic.issued_at, ic.id
        FOR NO KEY UPDATE OF ic
    )
    , revoked AS (
        UPDATE issued_credentials ic
        SET is_revoked    = TRUE,
            revoked_at    = p_revoked_at,
            revoke_reason = p_reason
        WHERE ic.id IN (SELECT l.id FROM locked l)
          AND ic.is_revoked = FALSE
          AND ic.expires_at > p_revoked_at
        RETURNING ic.jti, ic.identity_id, ic.account_id, ic.project_id, ic.expires_at
    )
    SELECT r.jti, r.identity_id, r.account_id, r.project_id, r.expires_at
    FROM revoked r;
END;
$$ LANGUAGE plpgsql;
