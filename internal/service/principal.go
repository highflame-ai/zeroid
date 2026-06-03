package service

import (
	"context"
	"errors"
)

// Principal is the resolved caller at /oauth2/authorize. The fields here
// become the {aid, pid, uid, oid, scp} claims on the issued auth-code JWT
// and travel through to the access token minted at code exchange.
//
// Resolvers (see PrincipalResolver) build a Principal from whatever
// authentication material the request carried — an api_key, a session
// cookie, an mTLS chain. zeroid is intentionally agnostic about how the
// principal is authenticated; it only knows what the resolved tenant +
// user identifiers are.
//
// Defined in package service so internal/handler can reference it directly
// (handler is below zeroid in the dependency tree). The top-level zeroid
// package re-exports it as a type alias for the public API surface
// deployers see.
type Principal struct {
	// AccountID and ProjectID are required — they define the tenant
	// scope of the issued authorization code. An authorization code
	// minted without a tenant context would produce a token unbound
	// from multi-tenancy; zeroid rejects an empty AccountID at
	// IssueAuthCode time.
	AccountID string
	ProjectID string

	// UserID is the human (or workload) the issued token will be bound
	// to. Optional — when empty, zeroid issues a tenant-bound token
	// with no user binding. Resolvers SHOULD populate this whenever the
	// underlying credential names a user (e.g. an API key whose
	// `created_by` field carries the developer's user ID).
	UserID string

	// OrgID is an optional organisational identifier above account-
	// level scope. Populated only when the resolver has a meaningful
	// value; the auth-code JWT carries it in the `oid` claim and the
	// downstream access token surfaces it for resource servers that
	// need cross-account org context.
	OrgID string

	// Scopes is the resolver-narrowed list of scopes the principal is
	// allowed to obtain. The /oauth2/authorize handler intersects this
	// with the OAuth client's registered scope surface and the caller-
	// requested scope before stamping the authorization code. Empty
	// means "no resolver-side narrowing".
	Scopes []string
}

// AuthorizeRequest is a typed, read-only snapshot of the parsed
// /oauth2/authorize request handed to every PrincipalResolver. Built by
// zeroid from the inbound *http.Request once and reused across the
// resolver chain. Resolvers never see net/http types directly — that's
// deliberate. zeroid's whole surface accepts typed structs (TokenRequest,
// BcAuthorizeInput, IssueAuthCodeRequest); this snapshot keeps the
// extensibility hook consistent with that pattern instead of letting one
// hook leak transport-layer details into deployer code.
//
// The Form / Header / Cookie accessors expose the source request's
// fields without exposing the request itself. Resolvers can read any
// header or form value they need (api_key form param, session cookie,
// mTLS chain header) — they just can't mutate the request, re-parse the
// body, or call ServeHTTP-level helpers. Multi-value headers collapse
// to comma-joined per RFC 9110 §5.3; fields missing from the request
// return the empty string.
type AuthorizeRequest struct {
	// Standard OAuth 2.0 + PKCE fields (RFC 6749 §4.1.1, RFC 7636 §4.3).
	// Parsed and validated by zeroid before resolvers see them.
	ClientID            string
	RedirectURI         string
	ResponseType        string
	CodeChallenge       string
	CodeChallengeMethod string
	State               string
	Scope               string

	// Form returns a body form value parsed by zeroid, or "" if absent.
	// Resolvers use this to read principal-credential fields they own
	// (e.g. "api_key" for the api_key resolver, "session_id" for a
	// session-cookie resolver fallback path).
	Form func(name string) string

	// Header returns a request header value, or "" if absent. Multi-
	// value headers collapse to a comma-joined string per RFC 9110 §5.3.
	Header func(name string) string

	// Cookie returns a request cookie value by name, or "" if absent.
	Cookie func(name string) string
}

// PrincipalResolver authenticates the caller at /oauth2/authorize and
// returns the resolved Principal whose tenant + user context will be
// baked into the issued authorization code.
//
// Resolvers are registered with Server.RegisterPrincipalResolver (in the
// top-level zeroid package) and tried in registration order. The first
// resolver to return a non-nil Principal wins. A resolver that doesn't
// apply to the current request (e.g. the api_key resolver seeing no
// api_key form field) MUST return (nil, ErrPrincipalNotApplicable) —
// that signals "skip me, try the next one." Any other returned error
// fails the request immediately with 401 invalid_client, and the
// resolver chain stops.
//
// Resolvers run in the request goroutine — keep them fast (no network
// I/O beyond cache hits, no DB queries beyond in-process pools). The
// only DB call zeroid expects from a typical resolver is a single
// credential lookup (e.g. ResolveAPIKey).
type PrincipalResolver func(ctx context.Context, req *AuthorizeRequest) (*Principal, error)

// ErrPrincipalNotApplicable is the sentinel a PrincipalResolver returns
// when the current request does not carry the kind of credential the
// resolver handles. zeroid moves to the next registered resolver. When
// every resolver returns this sentinel, the chain has no applicable
// principal and the request fails with 401 invalid_client.
//
// Distinguish this from a credential-found-but-invalid error (a wrong
// api_key, an expired cookie): those return a non-sentinel error so
// zeroid fails fast with the resolver's specific reason instead of
// silently trying the next one. "Not applicable" is a positive signal
// the resolver doesn't see itself in this request — not "this request
// is invalid."
var ErrPrincipalNotApplicable = errors.New("zeroid: principal resolver not applicable")
