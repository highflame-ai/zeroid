-- 057_external_issuer_trust_email.up.sql
-- A person issuer can vouch for its own email claim (trust_email). OpenID
-- Connect returns email_verified from the UserInfo endpoint, not in the ID
-- token, whenever the sign-in also issued an access token (OIDC Core 5.4), so
-- an organization's own directory may never put it in the tokens ZeroID sees.
-- docs/external-issuers.md describes the rule.
--
-- A constant default adds the column without a table rewrite.
SET LOCAL lock_timeout = '3s';

ALTER TABLE external_issuers ADD COLUMN IF NOT EXISTS trust_email BOOLEAN NOT NULL DEFAULT false;
