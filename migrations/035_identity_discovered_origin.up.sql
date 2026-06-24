-- 035: identity discovery support — add the `discovered` lifecycle state and
-- the `origin` provenance discriminator (ADR 0009 D2 / docs/identity-lifecycle.md).
--
-- `discovered` sits below `pending` in the ISO/IEC 24760-shaped lifecycle: an
-- identity observed in an external IdP via a discovery connector — owner-optional
-- and credential-less until adopted. `origin` distinguishes `native` (ZeroID
-- issued it) from the external ecosystem it was discovered in. There is ONE
-- identity registry; discovered rows are not a separate store, they are
-- distinguished by origin + status (see docs/identity-lifecycle.md).

-- Superset of the existing constraint — every existing row already satisfies it,
-- so the re-validation is a fast metadata check (matches migration 032).
ALTER TABLE identities
    DROP CONSTRAINT identities_status_check,
    ADD CONSTRAINT identities_status_check
        CHECK (status IN ('discovered', 'pending', 'active', 'suspended', 'deactivated', 'expired'));

-- NOT NULL + DEFAULT on Postgres 11+ is a metadata-only add (no table rewrite,
-- no long lock). The CHECK enforces a clean lowercase identifier rather than a
-- closed ecosystem enum: the external set is open and grows with discovery
-- connectors in a separate service, so a hard enum here would couple ZeroID
-- releases to every new connector.
ALTER TABLE identities
    ADD COLUMN IF NOT EXISTS origin VARCHAR(50) NOT NULL DEFAULT 'native'
        CHECK (origin ~ '^[a-z0-9_]+$');

-- Discovery posture queries ("which external identities exist / are ownerless")
-- scan only the non-native slice. The partial index keeps native rows out so the
-- index stays small and the scan is O(discovered-rows), not O(all-identities).
CREATE INDEX IF NOT EXISTS idx_identities_origin
    ON identities (account_id, project_id, origin)
    WHERE origin <> 'native';
