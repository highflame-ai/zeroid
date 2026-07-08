-- Revert 038: drop the code-agent bootstrap constraint, index + columns.
-- Dropping the column also drops the partial index and CHECK, but the
-- explicit statements keep the intent clear.
--
-- Ordering: roll back the DEPLOYMENT first — post-038 binaries name these
-- columns in every identities SELECT (bun explicit column lists), so running
-- this down under new code breaks the whole auth plane, not just /code-agents.
ALTER TABLE identities DROP CONSTRAINT IF EXISTS identities_bootstrap_machine_id_not_empty;
DROP INDEX IF EXISTS idx_identities_bootstrap_machine;

ALTER TABLE identities DROP COLUMN IF EXISTS bootstrap_machine_id;
ALTER TABLE identities DROP COLUMN IF EXISTS last_attested_at;
ALTER TABLE identities DROP COLUMN IF EXISTS attestation_evidence;
