-- Dropping mission_id erases the delegation-tree linkage for every active
-- refresh-token family. After down + re-apply, refreshed access tokens will
-- re-root their mission (the pre-#81-fix behavior) until each family is
-- re-issued. No security impact — mission_id is an audit-correlation field —
-- but workflow-scoped audit queries lose continuity across the gap.

SET LOCAL lock_timeout = '3s';

ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS mission_id;
