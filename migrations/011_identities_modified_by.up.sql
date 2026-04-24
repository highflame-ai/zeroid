-- 009_identities_modified_by.up.sql
-- Adds modified_by to track the acting user on UPDATE/DELETE for the audit trigger.
-- The trigger reads NEW.modified_by (UPDATE) and OLD.modified_by (DELETE) to populate
-- caller_user_id in identity_audit_logs — matching admin's audit pattern.

ALTER TABLE identities
    ADD COLUMN IF NOT EXISTS modified_by VARCHAR(255) NOT NULL DEFAULT '';
