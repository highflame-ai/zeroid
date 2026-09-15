-- 044_refresh_token_resource.up.sql
-- Persist the RFC 8707 resource CEILING a refresh family was issued for, so
-- every rotation re-stamps the same binding on its successor access token
-- (CAP-IDN-027, zeroid#327, ADR 0037).
--
-- Until now a resource-bound authorization_code exchange was issued NO refresh
-- token at all. That was the fail-closed answer while the binding could not
-- survive rotation: the refresh path re-mints from state on this row, the
-- binding lived only in the access token's CustomClaims, and a rotated token
-- therefore came back silently UNBOUND — bind to server X, refresh, use
-- anywhere, with INV-IDN-006 enforcement gone quiet because its discriminator
-- claim had vanished.
--
-- Carrying it here is what makes issuing the refresh token safe, and the cost
-- of NOT issuing one was real: a desktop MCP client that bound correctly was
-- sent to a browser every hour, which made not binding the path of least
-- resistance. That is the likeliest way the invariant fails in practice.
--
-- TEXT[] rather than a scalar, matching grant_types / redirect_uris / scopes /
-- allowed_scopes elsewhere in this schema. The authorize leg caps the ceiling
-- at ONE value today, but cardinality is a constant, not a shape (ADR 0037 D2):
-- storing an array means raising that cap later is one constant, not a
-- representation migration on a live table. It also maps straight to []string
-- with no marshalling layer, which removes an error class rather than moving it.
--
-- NULL ⇒ no resource binding on this family — the ordinary authorization_code
-- flow and every pre-migration row — whose rotation is unchanged. Copied
-- verbatim onto each successor row on rotation, exactly like mission_id,
-- audience and dpop_key_thumbprint. THAT COPY IS THE WHOLE POINT: a ceiling
-- seeded at issuance but not carried forward survives the first rotation and is
-- lost on the second, which yields an unbound token with no error anywhere.
-- Covered by TestResourceCeiling_SurvivesTwoRotations, which rotates twice for
-- exactly this reason.
--
-- No backfill needed: no resource-bound exchange has ever been issued a refresh
-- token (the suppression this change removes gated on exactly that), so there is
-- no existing row that ought to hold a value. NULL is correct for every row
-- already present, not a gap. Verified against the pre-change code rather than
-- assumed — only two call sites ever insert a refresh-token row, and the second
-- (the external-principal exchange) is structurally unreachable for a bound
-- request because `audience` and `resource` are mutually exclusive.
--
-- No index on the column itself: on the steady-state read path it is read only
-- alongside the row it lives on (claimed by token_hash, rotated within its
-- family), never filtered or joined on — same reasoning as migration 039's
-- `audience`. The partial index below is for the ROLLBACK path, not this one.
--
-- ── Lock posture, and the operational hazard behind it ──────────────────────
--
-- The ALTER itself is metadata-only on PG 11+ (nullable, no default): ACCESS
-- EXCLUSIVE but no table rewrite, sub-millisecond once acquired. The risk is the
-- lock QUEUE, not the ALTER — an ACCESS EXCLUSIVE request queues behind any
-- in-flight transaction holding ROW EXCLUSIVE on refresh_tokens, and while it
-- waits it blocks every reader and writer behind it. lock_timeout = '3s'
-- therefore authorises up to a 3-second stall of the whole token endpoint.
-- (3s matches migration 039's precedent on this table; consider a tighter value
-- with an operator-side retry if that stall is unacceptable for your window.)
--
-- Named conflicting workload, so this can be scheduled around it: the cleanup
-- worker runs an UNBATCHED `DELETE FROM refresh_tokens WHERE expires_at < ?` on
-- a ticker (internal/worker/cleanup.go). That is the long ROW EXCLUSIVE holder
-- most likely to make this ALTER hit its timeout. Do not apply 044 during a
-- sweep.
--
-- And know the failure mode before you start: golang-migrate marks the version
-- dirty BEFORE running the statement and clears it after, so a lock_timeout
-- abort leaves schema_migrations at (44, dirty). Because AutoMigrate defaults
-- to on, every pod then fails startup on ErrDirty — a 3-second lock wait
-- becomes an outage. Stage `migrate force 43` in the runbook.
--
-- Post-migration verification must check the column TYPE, not just its
-- presence: ADD COLUMN IF NOT EXISTS silently no-ops against a same-named
-- column of any type, and the dirty-state recovery above invites a hand-added
-- one. Assert `udt_name = '_text'` — a `resource text` column would leave this
-- migration green and every []string scan broken.

SET LOCAL lock_timeout = '3s';

ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS resource TEXT[];

-- An EMPTY array must never reach this column.
--
-- bun's `nullzero` collapses only a NIL slice to NULL — schema/zerochecker.go
-- maps reflect.Slice to isNil, not isZeroLen — so a non-nil empty []string
-- writes '{}' rather than NULL. Every consumer keys on len(ceiling) == 0, so
-- '{}' reads as "no ceiling", which is the WIDENING direction: it permits the
-- token request to bind to anything. It also round-trips stably, re-written as
-- '{}' by every rotation for the family's life.
--
-- No code path can produce it today (validateResourceIndicators returns nil for
-- empty input, and the decoder now rejects a present-but-empty `rsc` claim), but
-- the state is representable in the schema — and this table's own rollback
-- runbook puts an operator here with UPDATE statements, where `SET resource =
-- '{}'` instead of `= NULL` would silently unbind a family with no error
-- anywhere. A NULL element or an empty-string element is covered too: those
-- narrow rather than widen (a token bound to "" is dead everywhere), but they
-- are garbage states with no legitimate producer.
--
-- NOT VALID deliberately. It enforces on every new write, which is the half that
-- matters, without the full-table scan under ACCESS EXCLUSIVE that a validated
-- ADD CONSTRAINT would take. Every existing row has resource IS NULL and so
-- already satisfies it; a follow-up migration can VALIDATE CONSTRAINT out of
-- band once the table size is known.
-- cardinality(), NOT array_length(). array_length('{}'::text[], 1) returns NULL
-- rather than 0, so `array_length(...) >= 1` evaluates to NULL for an empty
-- array, the whole conjunction collapses to NULL, and a CHECK that evaluates to
-- NULL is treated as SATISFIED — meaning the constraint would have permitted
-- '{}', the one case it exists for. cardinality('{}') is 0 and compares
-- normally. Verified against Postgres for NULL, '{}', '{NULL}', '{""}' and
-- populated arrays.
-- Wrapped in a DO block because Postgres has no ADD CONSTRAINT IF NOT EXISTS,
-- and every other statement in this file is idempotent. Without this, a
-- re-run — which the dirty-state recovery above can invite — hard-fails on
-- "constraint already exists" where the rest of the file would no-op.
DO $$
BEGIN
    ALTER TABLE refresh_tokens
        ADD CONSTRAINT refresh_tokens_resource_nonempty
        CHECK (
            resource IS NULL
            OR (cardinality(resource) >= 1
                AND array_position(resource, NULL) IS NULL
                AND '' <> ALL (resource))
        ) NOT VALID;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END
$$;

-- DELIBERATELY NO INDEX ON `resource`, on either the read path or the rollback
-- path.
--
-- The rollback runbook in the down migration needs `WHERE resource IS NOT
-- NULL`, and an earlier revision of this file added a partial index for it on
-- the reasoning that a plain CREATE INDEX is "free" against zero qualifying
-- rows. That was wrong twice over:
--
--   * A PARTIAL index build still evaluates its predicate for every row, so it
--     is a full heap scan no matter how few rows qualify.
--   * golang-migrate sends this whole file as ONE implicit transaction, so the
--     ACCESS EXCLUSIVE lock taken by the ALTER above is still held during the
--     build. Verified via pg_locks. That blocks readers as well as writers —
--     strictly worse than migration 033's posture on this same table, where a
--     standalone CREATE INDEX takes a SHARE lock that at least permits reads.
--
-- So the index would have made every deploy of 044 pay an exclusive-locked full
-- scan to speed up a query that may never run. The revoke is a one-off
-- emergency step where a sequential scan is acceptable; if it ever needs to be
-- fast, add the index in its OWN migration with CREATE INDEX CONCURRENTLY,
-- which cannot run inside this file's implicit transaction.
