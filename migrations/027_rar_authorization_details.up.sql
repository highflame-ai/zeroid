-- 027_rar_authorization_details.up.sql
-- RFC 9396 OAuth 2.0 Rich Authorization Requests (RAR).
--
-- CIBA + RAR is the standards-compliant way to say "approve this specific
-- transaction" rather than "approve this scope" — the agent passes a typed
-- JSON envelope describing the action's intent (tool name, target, params,
-- AARM context-chain hash, etc.) on POST /oauth2/bc-authorize. ZeroID
-- persists the array verbatim so the approver UX can render the typed
-- details and the resource server can read them back at token-introspection
-- time (the latter wired in a follow-up PR).
--
-- Storage shape:
--   * JSONB column on backchannel_auth_requests
--   * NOT NULL DEFAULT '[]'::jsonb so pre-RAR rows (no authorization_details
--     supplied by the client) read as an empty array, not NULL — keeps the
--     consumer code branch-free
--   * No GIN index in v1; nothing today queries by authorization_details
--     content. Add one in a follow-up if usage emerges
--
-- Validation depth at parse time is intentionally permissive: ZeroID checks
-- only the outer shape (array of JSON objects, each with a non-empty string
-- `type` field). Per-type schema validation is opt-in via the
-- Server.RegisterAuthorizationDetailValidator hook so deployers like
-- Highflame can layer strict checks (e.g. highflame_tool_call: tool name
-- must be in the registered tool catalog) without zeroid committing to
-- any specific application schema.

ALTER TABLE backchannel_auth_requests
    ADD COLUMN IF NOT EXISTS authorization_details JSONB NOT NULL DEFAULT '[]'::jsonb;
