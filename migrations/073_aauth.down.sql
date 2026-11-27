-- 073_aauth.down.sql
DROP TABLE IF EXISTS aauth_enrollments;
DROP TABLE IF EXISTS aauth_ps_revocations;
ALTER TABLE credential_policies DROP COLUMN IF EXISTS aauth_person_server;
DROP TABLE IF EXISTS aauth_bootstrap_redemptions;
