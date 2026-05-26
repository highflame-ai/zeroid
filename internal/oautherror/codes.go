// Package oautherror defines canonical OAuth 2.0 protocol error code constants
// for the codes ZeroID emits on the wire.
//
// Why this package exists: across the codebase these codes were originally
// scattered as bare string literals. String literals compile cleanly when
// mistyped, offer no autocomplete, and have no central source of truth tying
// each value back to the spec that defines it. This package replaces those
// bare strings with named constants grouped by RFC, so the canonical value
// for every emitted error code is verifiable against the spec.
//
// The constants are deliberately untyped string consts (not a typed alias)
// so they remain assignable to the many `string` parameter slots that
// existing emission sites already use, without forcing conversions at every
// call site. This is internal scaffolding, not a public API.
//
// Spec references:
//   - RFC 6749 §5.2 (token endpoint errors):
//     https://www.rfc-editor.org/rfc/rfc6749#section-5.2
//   - RFC 6750 §3.1 (Bearer Token error codes):
//     https://www.rfc-editor.org/rfc/rfc6750#section-3.1
//   - RFC 7591 §3.2.2 (DCR client registration errors):
//     https://www.rfc-editor.org/rfc/rfc7591#section-3.2.2
//   - RFC 7592 §2.3 (DCR management errors):
//     https://www.rfc-editor.org/rfc/rfc7592#section-2.3
//   - RFC 9396 §5.4 (RAR authorization_details errors):
//     https://www.rfc-editor.org/rfc/rfc9396#section-5.4
//   - RFC 9449 §5 (DPoP errors):
//     https://www.rfc-editor.org/rfc/rfc9449#section-5
//
// Scope: this package covers ONLY OAuth-spec-defined error codes. Highflame-
// or product-specific codes that aren't defined by an RFC (e.g.
// "policy_violation" in extractOAuthError) stay as bare string literals at
// their emission sites — they have no canonical RFC source for this package
// to anchor on, and adding them here would dilute the "every constant maps
// to a clause in a published RFC" invariant. Future RFC-defined codes go
// here; future Highflame-internal codes either stay literal or move to a
// separate Highflame-namespaced constants package.
//
// Convention: the rule covers *emission sites* only — anywhere a wire-bound
// error code is produced (a call to oauthBadRequest, a header value, a JSON
// field). Comments and doc strings that quote a code by its literal value
// for documentation purposes (e.g. "// returns invalid_grant on …") may use
// the bare string. Grepping for "invalid_grant" should hit either the
// constant declaration in this file OR a comment, not an emission site.
package oautherror

// ── RFC 6749 §5.2 — token-endpoint error codes ──────────────────────────────
// https://www.rfc-editor.org/rfc/rfc6749#section-5.2
const (
	// InvalidClient indicates client authentication failed (unknown client,
	// no client authentication included, or unsupported authentication method).
	InvalidClient = "invalid_client"

	// InvalidGrant indicates the provided authorization grant (e.g.
	// authorization code, refresh token, assertion) or refresh token is
	// invalid, expired, revoked, does not match the redirection URI used in
	// the authorization request, or was issued to another client.
	InvalidGrant = "invalid_grant"

	// UnauthorizedClient indicates the authenticated client is not authorized
	// to use this authorization grant type.
	UnauthorizedClient = "unauthorized_client"

	// UnsupportedGrantType indicates the authorization grant type is not
	// supported by the authorization server.
	UnsupportedGrantType = "unsupported_grant_type"

	// InvalidScope indicates the requested scope is invalid, unknown,
	// malformed, or exceeds the scope granted by the resource owner.
	InvalidScope = "invalid_scope"

	// ServerError indicates the authorization server encountered an
	// unexpected condition that prevented it from fulfilling the request
	// (HTTP 500 equivalent, included in RFC 6749 §5.2 by reference from §4.1.2.1).
	ServerError = "server_error"
)

// ── RFC 6750 §3.1 — Bearer Token error codes ────────────────────────────────
// https://www.rfc-editor.org/rfc/rfc6750#section-3.1
const (
	// InvalidRequest indicates the request is missing a required parameter,
	// includes an unsupported parameter or parameter value, repeats the same
	// parameter, uses more than one method for including an access token, or
	// is otherwise malformed.
	InvalidRequest = "invalid_request"

	// InvalidToken indicates the access token provided is expired, revoked,
	// malformed, or invalid for other reasons.
	InvalidToken = "invalid_token"

	// InsufficientScope indicates the request requires higher privileges
	// than provided by the access token.
	InsufficientScope = "insufficient_scope"
)

// ── RFC 7591 §3.2.2 / RFC 7592 §2.3 — Dynamic Client Registration errors ────
// https://www.rfc-editor.org/rfc/rfc7591#section-3.2.2
// https://www.rfc-editor.org/rfc/rfc7592#section-2.3
const (
	// InvalidClientMetadata indicates the value of one of the client metadata
	// fields is invalid and the server has rejected this request.
	InvalidClientMetadata = "invalid_client_metadata"

	// InvalidRedirectURI indicates the value of one or more redirection URIs
	// is invalid.
	InvalidRedirectURI = "invalid_redirect_uri"

	// InvalidSoftwareStatement indicates the software statement presented is
	// invalid.
	InvalidSoftwareStatement = "invalid_software_statement"
)

// ── RFC 9396 §5.4 — Rich Authorization Requests ─────────────────────────────
// https://www.rfc-editor.org/rfc/rfc9396#section-5.4
const (
	// InvalidAuthorizationDetails indicates the authorization_details
	// parameter contains an unknown authorization details type or invalid
	// content.
	InvalidAuthorizationDetails = "invalid_authorization_details"
)

// ── RFC 9449 §5 — DPoP (Demonstrating Proof of Possession) ──────────────────
// https://www.rfc-editor.org/rfc/rfc9449#section-5
const (
	// InvalidDPoPProof indicates the DPoP proof JWT is missing, malformed,
	// has an invalid signature, or otherwise fails the validation rules of
	// RFC 9449 §4.3.
	InvalidDPoPProof = "invalid_dpop_proof"
)

// ── OpenID CIBA Core 1.0 §11 — Backchannel Authentication error codes ───────
// https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.11
const (
	// AuthorizationPending indicates the authorization request is still
	// pending — the end-user has not yet completed the user interaction.
	// Clients SHOULD continue polling after the interval returned in the
	// bc-authorize response.
	AuthorizationPending = "authorization_pending"

	// SlowDown indicates the client is polling /oauth2/token too frequently.
	// The poll interval is implicitly increased; clients MUST wait at least
	// the new interval before polling again.
	SlowDown = "slow_down"

	// ExpiredToken indicates the auth_req_id has expired and the request is
	// no longer redeemable. The client MUST start a new authentication
	// request via /oauth2/bc-authorize.
	ExpiredToken = "expired_token"

	// AccessDenied indicates the end-user or the authorization server denied
	// the request. Also used for state-machine violations (e.g. polling a
	// push-delivery auth_req_id, redeeming an already-redeemed code) where
	// no other code applies.
	AccessDenied = "access_denied"
)
