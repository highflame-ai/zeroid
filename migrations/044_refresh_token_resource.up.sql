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
-- No backfill, and none is possible or needed: no resource-bound exchange has
-- ever been issued a refresh token, so there is no existing row that ought to
-- hold a value. NULL is correct for every row already present, not a gap.
--
-- No index: read only alongside the row it lives on (claimed by token_hash,
-- rotated within its family), never filtered or joined on. Same reasoning as
-- migration 039's `audience`.
--
-- Lock posture: metadata-only ADD COLUMN on PG 11+ (nullable, no default), so
-- ACCESS EXCLUSIVE but not a table rewrite. lock_timeout scopes any blocking
-- acquire rather than letting it queue behind a long transaction.

SET LOCAL lock_timeout = '3s';

ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS resource TEXT[];
