ALTER FUNCTION revoke_credential_cascade(uuid, text, text, timestamptz, text)
    RESET enable_hashjoin
    RESET enable_mergejoin;

ALTER FUNCTION revoke_credentials_cascade(uuid, timestamptz, text)
    RESET enable_hashjoin
    RESET enable_mergejoin;

ALTER FUNCTION revoke_credentials_by_owner(text, text, timestamptz, text)
    RESET enable_hashjoin
    RESET enable_mergejoin;
