-- 036: discovery source provenance — add `source_id` so a connector sync can
-- prune only the identities IT discovered. A tenant may run several connectors
-- of the same origin (e.g. two Okta orgs), so origin alone can't disambiguate
-- which sync owns a discovered row. source_id is opaque to ZeroID — the
-- discovery service assigns it (a connector id / sync-source handle).
--
-- NULL for native identities and for discovered rows ingested without a source.
-- Metadata-only add on Postgres 11+ (nullable, no default) — no table rewrite.
ALTER TABLE identities
    ADD COLUMN IF NOT EXISTS source_id VARCHAR(255);

-- Supports per-source listing and the stale-prune sweep, which filters on
-- (account_id, project_id, origin, source_id). Partial: only discovered-from-a-
-- source rows carry a source_id, so native rows stay out of the index.
CREATE INDEX IF NOT EXISTS idx_identities_source
    ON identities (account_id, project_id, origin, source_id)
    WHERE source_id IS NOT NULL;
