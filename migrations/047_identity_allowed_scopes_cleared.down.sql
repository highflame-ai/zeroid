-- 047_identity_allowed_scopes_cleared.down.sql
-- The up migration cleared data it did not keep, so there is nothing to
-- restore. No grant reads the column after 047, so the cleared values do not
-- change any token either way.
SELECT 1;
