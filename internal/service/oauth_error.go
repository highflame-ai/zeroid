package service

import "net/http"

// OAuthError is the structured error type returned by OAuthService methods.
//
// Using a concrete type (rather than fmt.Errorf("code: ...") strings) has two
// benefits:
//   - The full error chain is preserved: Err is accessible via errors.Unwrap and
//     shows up in structured logs (zerolog's Err() field follows the chain).
//   - extractOAuthError in the handler uses errors.As — no brittle string parsing.
type OAuthError struct {
	// Code is the RFC 6749 §5.2 error code (e.g. "invalid_grant", "invalid_client").
	Code string
	// Description is the human-readable message returned in error_description.
	Description string
	// HTTPStatus is the HTTP response status code (400, 401, or 500).
	HTTPStatus int
	// err is the underlying cause; preserved for logging, not sent to clients.
	err error
}

// Error implements the error interface.
// The format is "code: description" — suitable for logging and OAuth responses.
// The underlying cause is accessible via Unwrap, not included in the string
// (to avoid leaking internal details into client-visible messages).
func (e *OAuthError) Error() string {
	if e.Description != "" {
		return e.Code + ": " + e.Description
	}
	return e.Code
}

// Unwrap returns the underlying cause, enabling errors.Is / errors.As traversal.
func (e *OAuthError) Unwrap() error {
	return e.err
}

// oauthBadRequest returns an *OAuthError with HTTP 400 and no underlying cause.
func oauthBadRequest(code, description string) *OAuthError {
	return &OAuthError{Code: code, Description: description, HTTPStatus: http.StatusBadRequest}
}

// oauthBadRequestCause returns an *OAuthError with HTTP 400 and a wrapped cause.
func oauthBadRequestCause(code, description string, cause error) *OAuthError {
	return &OAuthError{Code: code, Description: description, HTTPStatus: http.StatusBadRequest, err: cause}
}

// oauthUnauthorized returns an *OAuthError for invalid_client with HTTP 401.
func oauthUnauthorized(description string, cause error) *OAuthError {
	return &OAuthError{Code: "invalid_client", Description: description, HTTPStatus: http.StatusUnauthorized, err: cause}
}

// oauthServerError returns an *OAuthError for server_error with HTTP 500.
func oauthServerError(description string, cause error) *OAuthError {
	return &OAuthError{Code: "server_error", Description: description, HTTPStatus: http.StatusInternalServerError, err: cause}
}
