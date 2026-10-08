-- 048_ciba_approver_binding.up.sql
-- CIBA approver binding: bc-authorize extension parameters and the approval
-- record.
--
--   four_eyes, requester_owner  bc-authorize extension parameters. With
--                               four_eyes set, the user named by
--                               requester_owner may not resolve the request.
--   approver_iss, approver_auth,
--   channel_client_id           how the resolving user was authenticated
--                               (approver_auth: session | channel_attested).
--   hint_satisfied              which binding check the resolving user met
--                               (login_hint | group_hint).
--   shadow_would_deny,
--   shadow_reason               backchannel.enforce_hints=shadow: the
--                               resolution was allowed but would have been
--                               refused under enforce_hints=on.
--
-- Every column is NOT NULL with a constant default, so existing rows read as
-- "no extension parameters, nothing recorded" without NULL checks in consumer
-- code (the convention 028 set for group_hint). Constant defaults make each
-- ADD COLUMN metadata-only on PG 11+; lock_timeout bounds the wait for the
-- ACCESS EXCLUSIVE lock behind in-flight transactions (044's precedent).
SET LOCAL lock_timeout = '3s';

ALTER TABLE backchannel_auth_requests
    ADD COLUMN IF NOT EXISTS four_eyes         BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS requester_owner   TEXT    NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS approver_iss      TEXT    NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS approver_auth     TEXT    NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS channel_client_id TEXT    NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS hint_satisfied    TEXT    NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS shadow_would_deny BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS shadow_reason     TEXT    NOT NULL DEFAULT '';
