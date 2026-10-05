-- 048_credential_policy_jwt_typ.up.sql
-- Per-policy choice of the access token's JOSE `typ` header (D9 of
-- human-rooted delegation, highflame-authn#239).
--
-- Two specs ZeroID follows disagree on this one header, and a token cannot
-- satisfy both:
--
--   RFC 9068 §2.1   a JWT access token is typed `at+jwt`, so a resource server
--                   can tell it apart from an ID token.
--   JWT-SVID §2.3   `typ`, if set, MUST be `JWT` or `JOSE`.
--
-- The default is `at+jwt`, under either token profile. A policy sets `JWT`
-- for agents whose tokens must stay valid JWT-SVIDs (SPIFFE-strict consumers).
-- NULL means the default.
--
-- A nullable column with no default: catalog-only, no table rewrite.
SET LOCAL lock_timeout = '5s';

ALTER TABLE credential_policies
    ADD COLUMN IF NOT EXISTS jwt_typ VARCHAR(10)
        CONSTRAINT credential_policies_jwt_typ_check
        CHECK (jwt_typ IN ('at+jwt', 'JWT'));
