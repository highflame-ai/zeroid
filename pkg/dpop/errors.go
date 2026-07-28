package dpop

import (
	"errors"
	"fmt"
)

// Stable error codes — these are part of the package's public contract.
// Callers map them to RFC 9449 error responses (invalid_dpop_proof,
// invalid_token, WWW-Authenticate scheme="DPoP", etc.).
const (
	CodeInvalidProof         = "invalid_dpop_proof"
	CodeInvalidSignature     = "invalid_signature"
	CodeReplay               = "dpop_replay_detected"
	CodeBodyHashMismatch     = "body_hash_mismatch"
	CodeBodyHashRequired     = "body_hash_required"
	CodeTokenBindingMismatch = "cnf_jkt_mismatch"
	CodeUnsupportedAlg       = "unsupported_algorithm"
	CodeClockSkew            = "iat_outside_window"
	CodeHTUMismatch          = "htu_mismatch"
	CodeHTMMismatch          = "htm_mismatch"
	CodeATHMismatch          = "ath_mismatch"
	CodeStorageFailure       = "replay_store_failure"
)

// Sentinel errors for use with errors.Is. Each carries the stable code in its
// message so wrapping with %w preserves both the chain and the human-readable
// trail.
var (
	ErrInvalidProof         = newSentinel(CodeInvalidProof, "proof is malformed or fails structural validation")
	ErrInvalidSignature     = newSentinel(CodeInvalidSignature, "proof signature is invalid")
	ErrReplay               = newSentinel(CodeReplay, "proof jti has already been observed within the freshness window")
	ErrBodyHashMismatch     = newSentinel(CodeBodyHashMismatch, "proof bh claim does not match request body hash")
	ErrBodyHashRequired     = newSentinel(CodeBodyHashRequired, "proof is missing required bh claim for body-bearing request")
	ErrTokenBindingMismatch = newSentinel(CodeTokenBindingMismatch, "proof jwk thumbprint does not match access token cnf.jkt")
	ErrUnsupportedAlg       = newSentinel(CodeUnsupportedAlg, "proof signing algorithm is not in the allow-list")
	ErrClockSkew            = newSentinel(CodeClockSkew, "proof iat is outside the configured freshness window")
	ErrHTUMismatch          = newSentinel(CodeHTUMismatch, "proof htu claim does not match request URL")
	ErrHTMMismatch          = newSentinel(CodeHTMMismatch, "proof htm claim does not match request method")
	ErrATHMismatch          = newSentinel(CodeATHMismatch, "proof ath claim does not match access token hash")
	ErrStorageFailure       = newSentinel(CodeStorageFailure, "replay store is unavailable")
)

// Error is the typed error returned by Verifier methods. Callers can extract
// the stable Code with errors.As(err, &dpopErr) and branch on it without
// pattern-matching on message strings.
//
//	var de *dpop.Error
//	if errors.As(err, &de) {
//	    switch de.Code {
//	    case dpop.CodeReplay:
//	        // 401 invalid_dpop_proof; clock-sync hint in WWW-Authenticate
//	    case dpop.CodeStorageFailure:
//	        // 503 — the store is down, not the client's fault
//	    default:
//	        // 401 invalid_dpop_proof with the stable Code as error_description
//	    }
//	}
type Error struct {
	// Code is one of the Code* constants. Stable across versions.
	Code string
	// Message is a human-readable diagnostic. Safe to log; not safe to
	// surface verbatim to untrusted clients (may leak server-side state).
	Message string
	// cause is the wrapped underlying error (e.g. a JWS parse error or a
	// DB error). Use errors.Unwrap to inspect.
	cause error
}

func (e *Error) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("dpop: %s (%s): %v", e.Message, e.Code, e.cause)
	}
	return fmt.Sprintf("dpop: %s (%s)", e.Message, e.Code)
}

func (e *Error) Unwrap() error { return e.cause }

// Is supports errors.Is checks against sentinel errors and against other
// *Error values with the same Code.
func (e *Error) Is(target error) bool {
	if t, ok := target.(*Error); ok {
		return e.Code == t.Code
	}
	return false
}

// IsClientFault returns true for errors caused by the client's proof being
// malformed, mis-signed, replayed, or otherwise invalid — i.e. errors that
// map to 4xx responses. Returns false for ErrStorageFailure (5xx) and unknown
// errors (treat as 5xx to be safe).
func IsClientFault(err error) bool {
	var de *Error
	if !errors.As(err, &de) {
		return false
	}
	return de.Code != CodeStorageFailure
}

func newSentinel(code, msg string) *Error {
	return &Error{Code: code, Message: msg}
}

// wrap creates a new *Error preserving a stable code and an underlying cause.
func wrap(code, msg string, cause error) *Error {
	return &Error{Code: code, Message: msg, cause: cause}
}

// withCause wraps a sentinel with an underlying cause without copying the
// sentinel's Message — keeps both errors.Is(err, ErrX) and Unwrap working.
func withCause(sentinel *Error, cause error) *Error {
	return &Error{Code: sentinel.Code, Message: sentinel.Message, cause: cause}
}
