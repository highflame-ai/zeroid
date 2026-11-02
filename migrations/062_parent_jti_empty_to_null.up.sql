-- Store NULL, not '', for credentials that have no parent.
--
-- domain.IssuedCredential.ParentJTI had no nullzero tag, so every root
-- credential (client_credentials, jwt_bearer, api_key, ...) was written with
-- parent_jti = ''. idx_issued_credentials_parent_jti is partial on
-- parent_jti IS NOT NULL, so it held every row, and the column's stats
-- reported one distinct value ('') in ~100% of rows. The planner then
-- estimated that each node in a delegation tree matches the whole table and
-- walked revoke_credential_cascade with a sequential scan per tree node.
-- Measured on 1.01M credentials: revoking an 11,111-node tree ran for
-- minutes and the revoke request failed with server_error.
--
-- Migration 060's comment already assumed undelegated rows are NULL; this
-- makes that true for existing rows and refreshes the stats so the next plan
-- sees it.

-- delegated_by_wimse_uri had the same missing tag. It isn't on the cascade
-- path, but its partial index (IS NOT NULL) held every row for the same
-- reason.
--
-- One UPDATE touches every root credential, so on a large installation run
-- it off-peak; both columns are indexed, so expect index bloat until vacuum.
-- lock_timeout fails fast rather than queueing behind a revocation holding a
-- row lock. A timeout leaves (62, dirty): recover with `migrate force 61`.
--
-- Idempotent (WHERE ... = ''), so it is safe to re-run by hand after the
-- rollout completes, to clear '' rows written by old-binary pods during it.
SET LOCAL lock_timeout = '5s';

UPDATE issued_credentials
SET parent_jti = NULLIF(parent_jti, ''),
    delegated_by_wimse_uri = NULLIF(delegated_by_wimse_uri, '')
WHERE parent_jti = '' OR delegated_by_wimse_uri = '';

-- Without this the planner keeps the old stats until autovacuum's next
-- analyze, and the cascade walk stays a sequential scan until then.
ANALYZE issued_credentials;
