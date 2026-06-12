-- 030_refresh_token_mission_id.up.sql
-- Carry mission_id (issue #81) across refresh-token rotation.
--
-- A refresh is continuity of an existing grant, not the origination of a new
-- delegation tree — yet today the refresh_token grant defaults mission_id to
-- the freshly minted credential's own JTI, re-rooting the mission on every
-- refresh and fragmenting a single workflow's delegation tree into N missions.
-- That breaks workflow-scoped audit queries (GET /credentials?mission_id=) for
-- any session that refreshes mid-flight.
--
-- This column persists the mission_id of the access token the refresh family
-- was minted alongside, is copied to the successor row on every rotation, and
-- is read back in refreshToken() so the refreshed access token inherits the
-- original mission instead of starting a new one. NULL ⇒ pre-migration family
-- (or a flow that never carried a mission_id); the refresh path falls back to
-- today's re-root behavior for those.
--
-- Opaque value contract (issue #81): consumers MUST treat mission_id as opaque
-- — do not assume it is a JTI, do not look up a credential by it.
--
-- No index: this column is only ever read alongside the row it lives on
-- (claimed by token_hash, rotated within its family), never filtered on.
--
-- Lock posture: metadata-only ADD COLUMN on PG 11+ (nullable, no default).

SET LOCAL lock_timeout = '3s';

ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS mission_id VARCHAR(255);
