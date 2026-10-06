-- 047_identity_allowed_scopes_cleared.up.sql
-- Clear the deprecated identities.allowed_scopes. The identity's credential
-- policy is now the only scope ceiling: no grant reads this column any more,
-- and the API refuses to set it. Values left behind would still be returned
-- on identity responses, where a consumer could read them as a ceiling that
-- no longer applies.
--
-- The column itself stays (NOT NULL DEFAULT '{}' since 001) so an older
-- binary still reads and writes it during a rollout; a later release drops it.
--
-- Lock posture: no DDL. ROW EXCLUSIVE on identities, and row locks on the
-- rows that still carry scopes only; reads and writes continue.
--
-- Idempotent. Not reversible: the down migration cannot restore the values.
--
-- modified_by names this migration, so the audit row the trigger writes for
-- each cleared identity is attributed to it (SystemCallerPrefix convention).

UPDATE identities
   SET allowed_scopes = '{}',
       modified_by    = 'system:migration_047_identity_allowed_scopes_cleared'
 WHERE cardinality(allowed_scopes) > 0;
