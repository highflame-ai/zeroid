-- 069_service_key_management_mark.up.sql
-- Records that an API key was marked for management by a caller marked with
-- WithManagementKeyWrite (ADR 0053 D3). ZeroID only stores the mark; the
-- embedding service decides what a marked key may do and checks its creator's
-- role on each call.
--
-- A constant default keeps the ADD COLUMN metadata-only; existing keys read
-- as unmarked.
SET LOCAL lock_timeout = '3s';

ALTER TABLE service_keys
    ADD COLUMN IF NOT EXISTS management BOOLEAN NOT NULL DEFAULT false;
