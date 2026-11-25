-- 070_first_contact_standing_adoption.up.sql
-- Standing adoption under an adopt issuer row. docs/external-issuers.md
-- ("Standing adoption") describes the behaviour; this file only states what
-- the database holds itself.
--
-- first_contact_updated_by and first_contact_updated_at say who last changed
-- first_contact or its mapping (069), and when: an identity an adopt row
-- activates records them, so its audit trail names the person whose standing
-- mapping adopted it. Empty and NULL on existing rows until a write sets one.
--
-- The per-row rate limit now counts the bindings first contact wrote under a
-- row in the last minute: those it created, and those it enabled when an
-- adopt row's standing mapping adopted an agent that was bound already.
-- Either write leaves updated_by = 'system:first_contact', so 069's partial
-- index on (issuer_id, created_at) WHERE created_by = ... is replaced by one
-- on updated_by and updated_at.
--
-- LOCK POSTURE. A nullable column and a constant default add the columns
-- without a table rewrite. The partial index on external_issuer_bindings is
-- built in place: that table is small, and only rows first contact writes
-- enter the index. lock_timeout bounds the wait for both locks. A timeout
-- leaves (70, dirty): recover with `migrate force 69` and run it again.
SET LOCAL lock_timeout = '3s';

ALTER TABLE external_issuers
    ADD COLUMN IF NOT EXISTS first_contact_updated_by VARCHAR(255) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS first_contact_updated_at TIMESTAMPTZ;

DROP INDEX IF EXISTS external_issuer_bindings_first_contact_idx;
CREATE INDEX IF NOT EXISTS external_issuer_bindings_first_contact_written_idx
    ON external_issuer_bindings (issuer_id, updated_at)
    WHERE updated_by = 'system:first_contact';
