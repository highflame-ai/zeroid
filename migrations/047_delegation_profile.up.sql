-- 047_delegation_profile.up.sql
-- Human-rooted delegation, phase 1 (highflame-architecture#359; zeroid work is
-- tracked in highflame-authn#223).
--
-- Two things land here:
--
-- 1. The principal of every credential, persisted. RFC 8693 §4.1 makes `sub`
--    the principal whose authority a chain uses, fixed for the life of the
--    chain. Storing it as the RFC 9493 issuer-plus-subject pair, with whether
--    it is a person or a workload, is what makes "revoke everything acting
--    for this person" one indexed lookup instead of a walk (phase 2). The
--    columns are written for every tenant, whatever its token profile, so a
--    chain minted today is reachable when per-user revocation ships.
--    Rows written before this migration stay NULL: they cannot be reached by
--    per-user revocation, and owner revocation keeps working as before.
--
--    refresh_tokens gains principal_iss for the same reason: a refresh family
--    is revoked by (issuer, user), so two IdPs' `alice` never collide.
--
-- 2. The per-tenant token profile. `legacy` (the default) keeps today's claims
--    byte for byte, apart from additive fixes; `rfc8693` issues the RFC 8693
--    delegation shape. A tenant is (account_id, project_id), as everywhere
--    else in ZeroID. An absent row means `legacy`, so no backfill is needed
--    and every existing tenant is unaffected until it opts in.
--
-- LOCK POSTURE: golang-migrate runs this file in one transaction. Every
-- ALTER here adds a nullable column with no default, which Postgres records
-- in the catalog without rewriting the table, so the ACCESS EXCLUSIVE lock is
-- held only briefly. lock_timeout fails fast rather than queueing the auth
-- plane behind a long-running query. No index on the principal columns yet:
-- nothing in this release queries them, and issued_credentials keeps rows for
-- the audit-retention window (migration 037), so it can be large. The index
-- lands with the per-user revocation query that reads it, built CONCURRENTLY.
SET LOCAL lock_timeout = '5s';

ALTER TABLE issued_credentials
    ADD COLUMN IF NOT EXISTS principal_type VARCHAR(20),
    ADD COLUMN IF NOT EXISTS principal_sub  TEXT,
    ADD COLUMN IF NOT EXISTS principal_iss  TEXT;

ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS principal_iss TEXT;

CREATE TABLE IF NOT EXISTS tenant_settings (
    account_id    VARCHAR(255) NOT NULL,
    project_id    VARCHAR(255) NOT NULL,
    token_profile VARCHAR(20)  NOT NULL DEFAULT 'legacy'
        CONSTRAINT tenant_settings_token_profile_check
        CHECK (token_profile IN ('legacy', 'rfc8693')),
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (account_id, project_id)
);
