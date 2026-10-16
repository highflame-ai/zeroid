-- Pin the single-token cascade walk to index nested loops.
--
-- Each recursive step joins issued_credentials.parent_jti to the worktable.
-- The planner can't see the worktable's real size and leans on column stats,
-- and parent_jti is NULL for every undelegated token, so stats gathered
-- before a delegation tree exists make an equality match look huge. It then
-- picks a hash join that seq-scans issued_credentials once per tree level.
-- Measured on 1.07M credentials: revoking an 11,111-node tree spent 2.4 s in
-- 5 full scans; with fresh stats, or with this pin under stale stats, the
-- same walk is 40-155 ms via idx_issued_credentials_parent_jti.
--
-- Only revoke_credential_cascade (RFC 7009 revoke of one token) is pinned:
-- it revokes one token's subtree, a small slice of the table. The identity
-- and owner cascades can revoke most of the table at once, where a hash join
-- is the better plan; pinning revoke_credentials_by_owner made a 1.05M-row
-- revocation 27% slower (321 s vs 253 s), so those keep the planner's choice.
--
-- The setting applies only inside the function. CREATE OR REPLACE FUNCTION
-- resets it, so a migration that redefines this function must carry the SET
-- clauses forward; TestCascadeFunctionsPinIndexWalk fails if one is dropped.
ALTER FUNCTION revoke_credential_cascade(uuid, text, text, timestamptz, text)
    SET enable_hashjoin = off
    SET enable_mergejoin = off;
