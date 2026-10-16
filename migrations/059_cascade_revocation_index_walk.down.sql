ALTER FUNCTION revoke_credential_cascade(uuid, text, text, timestamptz, text)
    RESET enable_hashjoin
    RESET enable_mergejoin;
