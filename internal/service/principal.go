package service

import (
	"context"
	"errors"
	"unicode"
	"unicode/utf8"
)

// MaxPrincipalUserEmailLength is the longest user email zeroid carries from a
// Principal into a token, in bytes: the RFC 5321 §4.5.3.1.3 path limit (256)
// less the two angle brackets.
const MaxPrincipalUserEmailLength = 254

// MaxPrincipalUserNameLength is the longest user display name zeroid carries
// from a Principal into a token, in bytes.
const MaxPrincipalUserNameLength = 256

// sanitizePrincipalAttribute returns v when it is a non-empty, valid UTF-8
// string of at most maxLen bytes with no control or format characters, and ""
// otherwise. It is the defensive floor for the display attributes a resolver
// attaches to a Principal (UserEmail, UserName): those end up as access-token
// claims a CLI prints, so a value that could reorder or hide text on a
// terminal (bidi overrides, zero-width characters, escape sequences) is
// dropped rather than signed. Dropping, not rejecting, because the attribute
// is display-only and a login must not fail over it.
//
// It does not check that an email is well formed — that is the resolver's
// job, since only it knows where the value came from.
func sanitizePrincipalAttribute(v string, maxLen int) string {
	if v == "" || len(v) > maxLen || !utf8.ValidString(v) {
		return ""
	}
	for _, r := range v {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ""
		}
	}
	return v
}

// Principal is the resolved caller at /oauth2/authorize. The fields here
// become the {aid, pid, uid, oid, uem, unm, scp} claims on the issued auth-code JWT
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

	// UserEmail and UserName are optional display attributes of the user
	// named by UserID — the address and display name a CLI shows on
	// `whoami`. When set, they travel in the authorization code and are
	// stamped as the `user_email` / `user_name` claims on the access token
	// minted at code exchange, and on every access token a refresh of that
	// grant mints.
	//
	// They are attributes the RESOLVER vouches for, read from the credential
	// it verified (a signed assertion, a session) — never from a raw request
	// parameter, which the client controls. They carry no authority: nothing
	// in zeroid authorizes on them, and resource servers must not either
	// (UserID is the subject). zeroid drops a value that is longer than
	// MaxPrincipalUserEmailLength / MaxPrincipalUserNameLength or that is not
	// valid, printable UTF-8 rather than failing the login, because a missing
	// display attribute is harmless and a refused login is not.
	//
	// Both ride in the authorization code, which is a signed but UNENCRYPTED
	// JWT delivered on the redirect URI — so they are visible to whatever sees
	// that URL (the user's own browser and the client receiving the code).
	UserEmail string
	UserName  string

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

	// Resource carries every occurrence of the RFC 8707 `resource`
	// parameter (CAP-IDN-027). A slice because §2 permits the parameter to
	// repeat, and reading only the first occurrence would silently drop a
	// resource the client asked to be bound to.
	//
	// Read from a single source per method — the query string on GET, the
	// body on POST — never a merge of both, for the same parameter-
	// smuggling reason the scalar fields above are.
	Resource []string

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
// that signals "skip me, try the next one." ErrPrincipalInteractionRequired
// and ErrPrincipalAccessDenied stop the chain with their documented
// meanings. Any other returned error fails the request immediately with
// 401 invalid_client, and the resolver chain stops.
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

// ErrPrincipalInteractionRequired is the sentinel a PrincipalResolver returns
// when it recognises the request as one a HUMAN could satisfy, but nobody is
// authenticated yet — a session-cookie resolver seeing no session, typically.
// It means "not a failure; send this user somewhere they can log in."
//
// It exists because PrincipalResolver returns (*Principal, error) and so cannot
// redirect. Without it a resolver's only options were to decline (which reads as
// "wrong credential type" and ends in access_denied) or to fail — neither of
// which starts a login. Returning this sentinel lets zeroid do the redirect on
// the resolver's behalf, so the resolver still never touches the transport.
//
// Distinguish all four:
//
//   - ErrPrincipalNotApplicable — "this is not my kind of credential." Try the
//     next resolver.
//   - ErrPrincipalInteractionRequired — "this IS my kind of request, and it can
//     be satisfied by logging in." Stop the chain and redirect.
//   - ErrPrincipalAccessDenied — "I authenticated the resource owner and they
//     said no." Stop the chain and report access_denied to the client.
//   - any other error — "I found my credential and it is bad." Stop and fail.
//
// Only honoured on GET, where a user agent exists to redirect, and only when the
// deployer has supplied a target via Server.SetInteractiveLoginURL. Returned on a
// POST, or with no target configured, it degrades to the same access_denied a
// declining chain produces — a resolver cannot conjure a login surface that the
// deployment does not have.
//
// Returning it stops the chain: a resolver that wants to defer to a later one
// should return ErrPrincipalNotApplicable instead.
var ErrPrincipalInteractionRequired = errors.New("zeroid: principal requires interactive authentication")

// ErrPrincipalAccessDenied is the sentinel a PrincipalResolver returns after it
// has authenticated the request and established that the resource owner
// DECLINED it — a user pressing "Deny" on a consent screen, typically. It may be
// wrapped; zeroid matches it with errors.Is.
//
// It exists for deployments whose login and consent surface is a separate
// front end. That front end authenticates the user, asks for consent, and then
// posts a signed statement of the outcome to /oauth2/authorize server-to-server.
// On approval the resolver returns a Principal and the front end receives the
// code redirect to hand to the browser. On denial the client still needs the
// RFC 6749 §4.1.2.1 error redirect — and the front end cannot build it, because
// only zeroid has validated client_id and redirect_uri. Returning this sentinel
// asks zeroid to build it.
//
// zeroid answers with a 302 to the client's validated redirect_uri carrying
// error=access_denied, a fixed error_description, the request's state (when
// one was sent) and the RFC 9207 iss parameter. Unlike every other failure at
// this endpoint, that redirect is issued on POST as well as GET: the POST
// caller here is the front end, and its job is to forward the Location to the
// user agent. That holds for self-asserted (CIMD) clients too, remote
// redirect_uri included: cimd.allowed_domains is enforced when the document
// resolves, before any resolver runs. A JSON access_denied body (403) is only
// a defensive fallback for a destination zeroid cannot redirect to at all.
// It also stops the resolver chain, and it outranks both
// ErrPrincipalNotApplicable and ErrPrincipalInteractionRequired when an error
// matches more than one sentinel.
//
// Only return it for a request the resolver has authenticated. A credential
// that fails to verify is an ordinary error, and a request the resolver does
// not handle is ErrPrincipalNotApplicable; a resolver that reported denial for
// an unauthenticated request would let anyone produce the error redirect.
var ErrPrincipalAccessDenied = errors.New("zeroid: resource owner denied the request")

// ErrNoResolversRegistered is the sentinel Server.resolvePrincipal
// returns when the /oauth2/authorize endpoint is reached but the
// deployer never registered any PrincipalResolver. The handler maps
// this to 503 Service Unavailable so embedders see a clear
// "you forgot to wire this up" signal — distinct from 401, which
// signals "you wired it up but no credential matched."
//
// This is a configuration error, not a runtime credential error;
// hence 503 (server is missing required configuration) rather than
// 500 (something went wrong). Surfacing it as its own sentinel lets
// the handler distinguish from the "all resolvers returned
// ErrPrincipalNotApplicable" case, which is a legitimate 401.
//
// AS metadata omits the authorization_code grant while the chain is
// empty (see handler.API.SetAuthorizationCodeAvailable), so a client
// never discovers a flow that would land here.
var ErrNoResolversRegistered = errors.New("zeroid: no principal resolvers registered")
