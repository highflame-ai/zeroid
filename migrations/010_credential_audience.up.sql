-- 010_credential_audience.up.sql
-- Persists the explicit `audience` supplied at credential issuance so rotation
-- can propagate it onto the new credential. NULL (or empty) means no audience
-- was specified — issuance defaults `aud` to the issuer URL on the JWT, and
-- rotation re-defaults in the same way.

ALTER TABLE issued_credentials
    ADD COLUMN IF NOT EXISTS audience TEXT[];
