-- 058_refresh_token_user_display.up.sql
-- Carry the user's display attributes on a refresh-token family.
--
-- An access token minted at the authorization_code grant names the user's
-- email and display name (user_email / user_name), taken from the principal
-- the /oauth2/authorize resolver produced. A refresh re-mints the access token
-- from the refresh-token row alone, so without these columns every refreshed
-- token silently dropped both claims, and a CLI showing "who am I" went blank
-- an hour after login. Copied verbatim onto every successor row on rotation,
-- like mission_id and principal_iss.
--
-- Display only: nothing authorizes on these values. They are personal data,
-- and live exactly as long as the refresh-token row, which the cleanup worker
-- deletes once it has expired (rotated-out rows keep their expires_at, so
-- they go at the same time as the family's last token).
--
-- Nullable, no default, no backfill. NULL ⇒ a family minted before this
-- migration or a grant that carried no display attributes; its refreshed
-- tokens carry neither claim, as before. Metadata-only ALTER on PG 11+.
SET LOCAL lock_timeout = '5s';

ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS user_email TEXT,
    ADD COLUMN IF NOT EXISTS user_name TEXT;
