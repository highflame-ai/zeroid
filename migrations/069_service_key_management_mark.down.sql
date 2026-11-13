-- 069_service_key_management_mark.down.sql
ALTER TABLE service_keys DROP COLUMN IF EXISTS management;
