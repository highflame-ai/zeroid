-- 064_backchannel_requesting_groups.down.sql
-- Roll the binary back first: a server running the up migration's code writes
-- this column on every bc-authorize request.
SET LOCAL lock_timeout = '3s';

ALTER TABLE backchannel_auth_requests
    DROP COLUMN IF EXISTS requesting_groups;
