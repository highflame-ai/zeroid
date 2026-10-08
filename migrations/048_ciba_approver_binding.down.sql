-- Reverting 048. Roll the binary back FIRST: bun enumerates model columns
-- explicitly, so a binary that knows these columns fails every
-- backchannel_auth_requests query against a schema without them.
SET LOCAL lock_timeout = '3s';

ALTER TABLE backchannel_auth_requests
    DROP COLUMN IF EXISTS shadow_reason,
    DROP COLUMN IF EXISTS shadow_would_deny,
    DROP COLUMN IF EXISTS hint_satisfied,
    DROP COLUMN IF EXISTS channel_client_id,
    DROP COLUMN IF EXISTS approver_auth,
    DROP COLUMN IF EXISTS approver_iss,
    DROP COLUMN IF EXISTS requester_act_sub,
    DROP COLUMN IF EXISTS requesting_jti,
    DROP COLUMN IF EXISTS requester_actor,
    DROP COLUMN IF EXISTS requester_sub,
    DROP COLUMN IF EXISTS requester_owner,
    DROP COLUMN IF EXISTS four_eyes;
