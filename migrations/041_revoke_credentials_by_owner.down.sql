-- 041_revoke_credentials_by_owner.down.sql
DROP FUNCTION IF EXISTS revoke_credentials_by_owner(TEXT, TEXT, TIMESTAMPTZ, TEXT);
