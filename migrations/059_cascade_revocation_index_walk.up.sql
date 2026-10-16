-- Pin the cascade-revocation walks to index nested loops.
--
-- Each recursive step joins issued_credentials.parent_jti to the worktable.
-- The planner can't see the worktable's real size and leans on column stats,
-- and parent_jti is NULL for every undelegated token, so stats gathered
-- before a delegation tree exists make an equality match look huge. It then
-- picks a hash join that seq-scans issued_credentials once per tree level.
-- Measured on 1.07M credentials:
-- revoking an 11,111-node tree spent 2.4 s in 5 full scans; with fresh stats,
-- or with this pin under stale stats, the same walk is 40-155 ms via
-- idx_issued_credentials_parent_jti.
--
-- A subtree is always a tiny slice of the table, so an index walk is always
-- the right plan here. Function-scoped settings apply only inside these
-- calls.
--
-- CREATE OR REPLACE FUNCTION resets these settings: any migration that
-- redefines one of these functions must carry the SET clauses forward.
-- TestCascadeFunctionsPinIndexWalk fails if one is dropped.
ALTER FUNCTION revoke_credential_cascade(uuid, text, text, timestamptz, text)
    SET enable_hashjoin = off
    SET enable_mergejoin = off;

ALTER FUNCTION revoke_credentials_cascade(uuid, timestamptz, text)
    SET enable_hashjoin = off
    SET enable_mergejoin = off;

ALTER FUNCTION revoke_credentials_by_owner(text, text, timestamptz, text)
    SET enable_hashjoin = off
    SET enable_mergejoin = off;
