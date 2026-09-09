package service

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/highflame-ai/zeroid/internal/oautherror"
)

// ── RFC 8707 resource indicators ─────────────────────────────────────────────
//
// `resource` is a REQUEST parameter naming the protected resource(s) a token is
// being minted for (CAP-IDN-026). It is the minting half of INV-IDN-006, whose
// enforcement half (Shield) gates on the `resource` CLAIM this parameter
// produces.
//
// The security model rests on one property: a resource binding only ever
// NARROWS. Stamping a resource on a token strictly reduces where that token is
// honoured and grants no authority the grant did not already carry. That is why
// ZeroID can accept an arbitrary caller-supplied identifier without a registry
// of known resource servers — the worst a caller can do by naming a resource
// that does not exist is mint a token nothing will accept. Any future change
// that makes `resource` widen anything (select a scope profile, pick a policy,
// route to a different identity) breaks this and needs a registry first.

// maxResourceIndicators bounds how many resources one request may name. RFC 8707
// sets no limit; an unbounded list would let a caller inflate every issued JWT
// (the values land in both `aud` and the `resource` claim) and, on the ID-JAG
// path, force a large subset comparison. Eight is far above the realistic case —
// a token is normally bound to exactly one MCP server — and far below anything
// that matters for token size.
const maxResourceIndicators = 8

// maxResourceIndicatorLen bounds each individual value. The count cap alone does
// NOT bound token size — eight megabyte-long URIs pass a count check and then
// land in `aud`, in the `resource` claim, in the signed JWT, in the credentials
// row, and in the error/log lines that echo them. 2 KiB is far above any real
// RFC 9728 identifier (`<origin>/mcp/<slug>` is tens of bytes) and far below
// anything that inflates a token. Mirrors maxObservedResourceLen, which the
// inventory path already enforces.
const maxResourceIndicatorLen = 2048

// validateResourceIndicators checks a `resource` request parameter against
// RFC 8707 §2 and returns the de-duplicated list to bind.
//
// Per §2 each value MUST be an absolute URI and MUST NOT include a fragment.
// The absolute-URI rule is what keeps the identifier globally meaningful: a
// relative reference ("/mcp/github") means nothing to a resource server that
// did not issue it, and Shield's origin comparison (sameOrigin) silently fails
// closed on one, so a token bound to a relative value would be dead on arrival
// in a way the client could not diagnose. The no-fragment rule matters because
// fragments are not sent over the wire — two identifiers differing only by
// fragment are the same resource to every party that matters, so accepting one
// would create bindings that compare unequal for no observable reason.
//
// A query component IS permitted (§2 explicitly allows it when the resource
// server uses one). Values are compared and stamped verbatim, with no
// normalization: the identifier a client sends must be byte-identical to what
// the resource server advertises in its RFC 9728 metadata, and silently
// canonicalizing (lowercasing a host, stripping a default port, adding a
// trailing slash) would produce a binding the client did not ask for.
//
// Duplicates are collapsed rather than rejected — repeating a resource is
// harmless and RFC 8707 §2 explicitly permits the parameter to appear multiple
// times, so a client that lists one twice gets what it asked for.
//
// Returns an *OAuthError with `invalid_target` (RFC 8707 §2 names this the
// error for an invalid or unknown resource) on any violation.
func validateResourceIndicators(resources []string) ([]string, error) {
	if len(resources) == 0 {
		return nil, nil
	}
	if len(resources) > maxResourceIndicators {
		return nil, oauthBadRequest(oautherror.InvalidTarget,
			fmt.Sprintf("too many resource indicators (max %d)", maxResourceIndicators))
	}

	out := make([]string, 0, len(resources))
	for _, raw := range resources {
		// A caller that sends `resource=` (empty) on a form body never reaches
		// here — the form-compat middleware drops valueless parameters per
		// RFC 6749 §3.2. A JSON caller can still send "", so reject explicitly
		// rather than binding a token to the empty string.
		if strings.TrimSpace(raw) == "" {
			return nil, oauthBadRequest(oautherror.InvalidTarget,
				"resource must not be empty")
		}
		// Checked before parsing so a pathological value is rejected without
		// url.Parse walking it, and the error never echoes the oversized input.
		if len(raw) > maxResourceIndicatorLen {
			return nil, oauthBadRequest(oautherror.InvalidTarget,
				fmt.Sprintf("resource exceeds the maximum length of %d bytes", maxResourceIndicatorLen))
		}
		// RFC 3986 §2 confines a URI to a subset of printable ASCII: anything
		// else — a space, a tab, a control character, a raw non-ASCII rune —
		// must be percent-encoded. url.Parse is lenient about several of these
		// (a space passes), so without this a value that can never match an
		// RFC 9728 advertisement is accepted and bound, then appears verbatim
		// in a signed token, an audit record and a log line where a space or an
		// embedded newline makes the identifier ambiguous to read.
		//
		// Rejecting outright rather than percent-encoding for the caller: the
		// identifier has to match what the resource server advertises byte for
		// byte, and silently repairing it would produce a binding the client
		// never asked for.
		if i := strings.IndexFunc(raw, func(r rune) bool { return r < 0x21 || r > 0x7e }); i >= 0 {
			return nil, oauthBadRequest(oautherror.InvalidTarget,
				fmt.Sprintf("resource contains a character that RFC 3986 requires be percent-encoded (offset %d)", i))
		}
		// Deliberately NOT TrimSpace'd into the parse: a value with surrounding
		// whitespace is a malformed identifier, not one to silently repair.
		u, err := url.Parse(raw)
		if err != nil {
			return nil, oauthBadRequestCause(oautherror.InvalidTarget,
				fmt.Sprintf("resource %q is not a valid URI", raw), err)
		}
		if !u.IsAbs() {
			return nil, oauthBadRequest(oautherror.InvalidTarget,
				fmt.Sprintf("resource %q must be an absolute URI (RFC 8707 §2)", raw))
		}
		// url.Parse accepts "https://" with no host and yields IsAbs()==true, so
		// the absolute check alone is not enough to reject a hostless value.
		//
		// Keyed on the "//" authority marker rather than an http/https allow-list:
		// any scheme that declares an authority must actually name one, so
		// "ftp://" and "foo://" are rejected on the same grounds as "https://".
		// A scheme with no authority component is left alone — "urn:example:mcp"
		// is a legitimate absolute URI with no host to require, and RFC 8707 §2
		// says absolute URI, not http(s) URL.
		if strings.Contains(raw, "://") && u.Host == "" {
			return nil, oauthBadRequest(oautherror.InvalidTarget,
				fmt.Sprintf("resource %q declares an authority but names no host", raw))
		}
		// Userinfo is rejected, and the rejection deliberately does NOT echo the
		// value back.
		//
		// A resource indicator is a public identifier that gets stamped into a
		// SIGNED token (both `aud` and the `resource` claim), persisted on the
		// credential row, recorded in the observed-resource inventory, and
		// logged. A userinfo component puts a password into every one of those,
		// and a signed JWT cannot be un-issued — so this is a durable disclosure
		// rather than a caller-harms-only-themselves mistake, and "a binding only
		// narrows" does not cover it.
		//
		// It is also confusable: in "https://a:80@b/x" a reader sees host "a"
		// port 80, while every URL parser resolves the origin to "b" — so an
		// auditor and the enforcement point disagree about which server a token
		// is bound to. The same repo already rejects userinfo on the analogous
		// redirect_uri check (redirectURIAllowed), so accepting it here was an
		// inconsistency rather than a decision.
		if u.User != nil {
			return nil, oauthBadRequest(oautherror.InvalidTarget,
				"resource must not include a userinfo component (RFC 8707 §2 identifiers are public)")
		}
		// Fragment is checked via the raw string as well as the parsed struct:
		// a trailing "#" parses to an empty Fragment but is still a fragment
		// component per RFC 3986 §3.5, and §2 forbids the component, not just a
		// non-empty one.
		if u.Fragment != "" || strings.Contains(raw, "#") {
			return nil, oauthBadRequest(oautherror.InvalidTarget,
				fmt.Sprintf("resource %q must not include a fragment (RFC 8707 §2)", raw))
		}
		if !slices.Contains(out, raw) {
			out = append(out, raw)
		}
	}
	return out, nil
}

// maxAuthorizeResourceIndicators bounds how many resources may be consented at
// /oauth2/authorize — the CEILING recorded on the authorization code
// (CAP-IDN-027).
//
// One, deliberately, and tighter than the token endpoint's cap. A multi-valued
// ceiling is what makes a multi-audience access token expressible, and RFC 8707
// §3 is explicit about the hazard: "if a bearer token has multiple intended
// recipients (audiences), then the token is valid at more than one protected
// resource and can be used by any one of those resources to access any of the
// others." At one, that shape cannot be requested here at all, rather than
// being permitted and then gated after the fact.
//
// This is a CONSTANT, not a shape. The `rsc` claim, the refresh row's column
// and the subset check are all multi-valued, so raising this to 2 or 3 is this
// one line plus the multi-audience policy gate — no migration, no claim-shape
// change, no compatibility window (ADR 0037 D2). Raising it also obliges a
// second look at the refresh rule, which rejects an omitted `resource` against
// a ceiling holding more than one value precisely so this cap and that rule
// cannot drift apart silently.
//
// The ID-JAG ceiling is unaffected: it comes from the assertion's own
// `resource` claim, not from this endpoint, and stays multi-valued.
const maxAuthorizeResourceIndicators = 1

// maxAuthorizeResourceTotalLen bounds the SERIALIZED size of the ceiling.
//
// Count is not what constrains this leg — length is. The ceiling lands in the
// `rsc` claim of an authorization code that travels back to the client in a
// redirect Location query string, and the token endpoint's own caps
// (maxResourceIndicators × maxResourceIndicatorLen) would admit 16 KiB of URIs
// into a URL, past both browser and reverse-proxy limits. A code that cannot be
// delivered fails in a way the client cannot diagnose.
//
// Bounding total length rather than only per-value length is what lets the
// count cap above move later without reopening the URL budget. 1 KiB is far
// above any real RFC 9728 identifier — `<origin>/mcp/<slug>` is tens of bytes —
// and far below anything that threatens a redirect.
const maxAuthorizeResourceTotalLen = 1024

// ValidateAuthorizeResource checks a `resource` parameter supplied at
// /oauth2/authorize and returns the consented ceiling to record on the code.
//
// Exported so the /oauth2/authorize handler can run it BEFORE principal
// resolution. That ordering is the handler's documented posture — a request
// doomed by its own parameters must not first be sent through a login surface —
// and it is why this gate cannot live only inside IssueAuthCode, which runs
// after the resolver chain. IssueAuthCode re-runs it regardless, so a
// programmatic caller bypassing the handler is still gated.
//
// Layered on validateResourceIndicators rather than duplicating it: the RFC
// 8707 §2 syntax rules are identical at both endpoints, and an identifier that
// would be rejected at the token endpoint must not be silently accepted here
// and then fail at redemption — the client would have completed a whole browser
// trip to obtain a code it can never exchange.
//
// Duplicates collapse before the count check, so `resource=X&resource=X` is one
// resource and passes, matching §2's position that repeating the parameter is
// harmless.
func ValidateAuthorizeResource(resources []string) ([]string, error) {
	// Drop valueless occurrences BEFORE validating. RFC 6749 §3.1 requires a
	// parameter sent without a value to be treated as omitted, and at
	// /oauth2/token that happens for free: oauthFormCompatMiddleware strips
	// valueless parameters before the body is bound. /oauth2/authorize
	// deliberately bypasses that middleware (it reads r.PostForm / the query
	// directly), and `resource` is read as a repeatable parameter — so
	// `?resource=` arrives here as []string{""} rather than disappearing, and
	// without this it would fail the request with invalid_target.
	//
	// That would be both a spec violation and a regression: a client appending
	// `resource=` from an unset variable used to have the parameter ignored and
	// the flow succeed. It would also diverge the two endpoints, which is
	// exactly what this function exists to prevent.
	//
	// Only EMPTY occurrences are dropped. A whitespace-only value is still a
	// malformed identifier and still rejected below, because a client that sent
	// " " meant something by it.
	present := make([]string, 0, len(resources))
	for _, r := range resources {
		if r != "" {
			present = append(present, r)
		}
	}

	out, err := validateResourceIndicators(present)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	if len(out) > maxAuthorizeResourceIndicators {
		return nil, oauthBadRequest(oautherror.InvalidTarget,
			fmt.Sprintf("at most %d resource indicator may be consented at /oauth2/authorize "+
				"(a multi-audience token is not issuable on this grant)",
				maxAuthorizeResourceIndicators))
	}
	total := 0
	for _, r := range out {
		total += len(r)
	}
	if total > maxAuthorizeResourceTotalLen {
		return nil, oauthBadRequest(oautherror.InvalidTarget,
			fmt.Sprintf("resource indicators exceed the maximum combined length of %d bytes",
				maxAuthorizeResourceTotalLen))
	}
	return out, nil
}

// narrowToCeiling restricts a token request's `resource` to the ceiling the
// authorization code recorded, and supplies the ceiling when the request names
// nothing (CAP-IDN-027).
//
// This is the whole point of recording a ceiling: the client SELECTS from what
// the human consented to and can never add to it. Under the single-value cap the
// subset check degenerates to equality, but it is written as a subset check —
// reusing narrowResourcesTo, the same function the ID-JAG path uses — so it
// keeps its meaning unchanged when the cap moves. A bespoke string equality here
// would have to be rewritten at that point.
//
// An empty ceiling means the code carried no consented resource, and the request
// binds directly (bindResourceOnIssue) exactly as it did before CAP-IDN-027.
// That case MUST keep working: a resource binding only ever narrows, granting no
// authority the grant did not already carry, so there is nothing a ceiling would
// protect against — and rejecting it would break every CAP-IDN-026 caller that
// sends `resource` only at the token endpoint.
func narrowToCeiling(ceiling, requested []string) ([]string, error) {
	if len(ceiling) == 0 {
		return requested, nil
	}
	return narrowResourcesTo(ceiling, requested)
}

// resolveRefreshResources decides what RFC 8707 binding a rotation re-stamps,
// given the ceiling recorded on the refresh family and what the request named
// (CAP-IDN-027).
//
// The rule is CARDINALITY-AWARE, and that is the point rather than an
// implementation detail. RFC 8707 §2.2 says a refresh token "is bound to the
// full original grant", which reads as "re-stamp the ceiling" — correct and
// unambiguous while the ceiling holds one value. But at two or more, re-stamping
// the whole ceiling mints a MULTI-AUDIENCE token by default, which is precisely
// §3's hazard: "if a bearer token has multiple intended recipients (audiences),
// then the token is valid at more than one protected resource and can be used by
// any one of those resources to access any of the others."
//
// So the omitted-`resource` case re-stamps only a single-valued ceiling and
// refuses a wider one, forcing the client to select. Written this way, raising
// maxAuthorizeResourceIndicators cannot quietly start minting multi-audience
// tokens: the cap and this rule are coupled deliberately so they cannot drift
// apart unnoticed. The alternative — requiring `resource` on every refresh of a
// bound family — was rejected because a conformant client can legitimately omit
// it: the MCP SDK decides per-request via should_include_resource_param against
// mutable context (protected-resource metadata can be discovered mid-session),
// so "require" would 400 a correct client at the moment its token expires.
//
// An unbound family (no ceiling) with a named resource NARROWS, which is always
// safe — it grants no authority the grant did not carry — and an unbound family
// with nothing named is unchanged.
func resolveRefreshResources(ceiling, requested []string) ([]string, error) {
	if len(requested) > 0 {
		return narrowToCeiling(ceiling, requested)
	}
	switch len(ceiling) {
	case 0:
		// Unbound family: rotation carries no `resource` claim, exactly as
		// before CAP-IDN-027.
		return nil, nil
	case 1:
		return ceiling, nil
	default:
		return nil, oauthBadRequest(oautherror.InvalidTarget,
			"this grant authorizes more than one resource: the refresh request must name "+
				"which one the access token is for (a multi-audience token is not issued by default)")
	}
}

// checkResourceAudienceExclusive rejects a request that carries BOTH the
// audience-profile `audience` parameter and the RFC 8707 `resource` parameter.
//
// The two look similar and both end up influencing `aud`, but they mean
// different things: `audience` names a server-defined SCOPE PROFILE (it widens —
// it adds that profile's fixed scope set), while `resource` names a protected
// resource (it only narrows). Letting them coexist would put two meanings on one
// claim with no discriminator — which is exactly the failure that made Shield
// deny every MCP-targeted request in prod (shield#366, INV-IDN-006). Refusing
// the combination outright means there is no precedence rule to get wrong, and
// no profiled-audience token ever also carries a resource binding.
//
// If a concrete need for "profiled AND resource-bound" ever appears, it needs a
// separate deliberate design (likely a distinct claim), not a precedence tweak
// here.
func checkResourceAudienceExclusive(req TokenRequest) error {
	if req.Audience != "" && len(req.Resource) > 0 {
		return oauthBadRequest(oautherror.InvalidRequest,
			"audience and resource are mutually exclusive: audience names a scope profile, "+
				"resource names an RFC 8707 protected resource")
	}
	return nil
}

// narrowResourcesTo restricts an authorized resource set to the subset the
// client requested, for grants where an upstream authority (today: an ID-JAG's
// own `resource` claim) already decided which resources are permissible.
//
// Every requested value MUST appear in authorized, compared as an exact string.
// This is the direction that makes the parameter safe here: the client SELECTS
// from what the IdP granted, and can never add to it. Comparison is exact
// because both sides are opaque identifiers — a prefix or origin match would let
// "https://gw.example/mcp/github-admin" be satisfied by an authorization for
// "https://gw.example/mcp/github".
//
// An empty request returns the full authorized set unchanged: omitting the
// parameter keeps the pre-CAP-IDN-026 behaviour, where the claim decides.
func narrowResourcesTo(authorized, requested []string) ([]string, error) {
	if len(requested) == 0 {
		return authorized, nil
	}
	for _, want := range requested {
		if !slices.Contains(authorized, want) {
			return nil, oauthBadRequest(oautherror.InvalidTarget,
				fmt.Sprintf("resource %q is not among the resources this grant authorizes", want))
		}
	}
	return requested, nil
}

// grantSupportsResource reports whether a grant honours the `resource`
// parameter. Grants are enabled here as their binding lands; anything not
// listed rejects the parameter outright (rejectUnsupportedResource) rather than
// accepting and ignoring it.
//
// refresh_token was deliberately absent until CAP-IDN-027, on the grounds that
// accepting a binding there would let a client re-target a token it already
// holds — the code called it "the second lock on that door", the first being
// that a resource-bound request was issued no refresh token at all.
//
// Both have been retired together, and the order matters: the lock existed
// ONLY because the binding was not carried across rotation. Now that the
// ceiling is recorded on the refresh family, the correct control is the subset
// check against it (resolveRefreshResources), and the blanket rejection is
// over-strict rather than protective — it 400s the exact request a conformant
// client makes, since the MCP SDK sends `resource` on the refresh leg too.
//
// Re-targeting is not merely disallowed now, it is INEXPRESSIBLE: the ceiling
// is capped at one value, so a client can only ever re-assert the single
// resource it consented to. The lock retires as verified inert, not as an
// accepted risk. That reasoning depends on maxAuthorizeResourceIndicators
// staying at 1 — raising it re-opens the question, which is why the
// omitted-`resource` path refuses a multi-valued ceiling outright.
var resourceSupportedGrants = map[string]bool{
	// jwt-bearer covers the ID-JAG profile, where `resource` SELECTS a subset of
	// the resources the corporate IdP already authorized (narrowResourcesTo).
	// The NHI self-signed jwt-bearer path shares this grant type and rejects the
	// parameter itself — see jwtBearer — because it has no authorized set to
	// narrow against.
	"urn:ietf:params:oauth:grant-type:jwt-bearer": true,
	// The ordinary grants bind directly (bindResourceOnIssue): there is no
	// upstream authorized set to narrow against, so the requested resource
	// simply restricts where the token they would have minted anyway is
	// honoured. This is the case zeroid#258 exists for — a resource-bound token
	// with no enterprise IdP in the loop.
	"client_credentials": true,
	"api_key":            true,
	"urn:ietf:params:oauth:grant-type:token-exchange": true,
	"authorization_code":                              true,
	// refresh_token SELECTS from the ceiling recorded on the refresh family
	// (resolveRefreshResources), the same narrows-only direction the ID-JAG
	// path uses. See the note above on why the previous blanket rejection was
	// removed rather than kept as defence in depth.
	"refresh_token": true,
}

func grantSupportsResource(grantType string) bool {
	return resourceSupportedGrants[grantType]
}

// bindResourceOnIssue stamps an RFC 8707 binding onto an issuance request.
//
// Two claims, deliberately, because they answer different questions:
//
//   - `aud` — RFC 8707 §2 conformance. A resource-indicator request produces a
//     token audienced to the resource, which is what a spec-following resource
//     server checks.
//   - `resource` — the discriminator INV-IDN-006 enforcement keys on. It cannot
//     read `aud` for this: ZeroID stamps `aud` on every token it issues,
//     defaulting to the issuer URL to satisfy JWT-SVID §3, so a non-empty `aud`
//     says nothing about whether a binding exists. Treating it as if it did
//     denied every MCP-targeted request in prod (shield#366). Presence of the
//     `resource` claim is the signal; its absence means "not bound".
//
// `resource` is in reservedClaims, so setting it here — the same direct-to-
// CustomClaims route the ID-JAG path uses — is the ONLY way it can appear. A
// caller can never inject or widen one through additional_claims, which is what
// keeps the claim's presence load-bearing.
//
// ── `aud` IS NOT AN AUTHORIZATION SIGNAL ─────────────────────────────────────
//
// Setting Audience here means that on the ordinary grants (client_credentials,
// api_key, token-exchange, authorization_code) the CALLER chooses `aud`. That is
// deliberate and safe only because nothing on this platform treats `aud` as an
// authorization input:
//
//   - Shield, Observatory, Cerberus, Discovery and AuthN all construct
//     authjwt.VerifierConfig with Issuer + JWKSURL and leave Audience unset.
//   - INV-IDN-006 enforcement keys on the `resource` claim precisely because
//     `aud` cannot carry that meaning — ZeroID stamps it on every token,
//     defaulting to the issuer URL for JWT-SVID §3.
//
// The "a binding only ever NARROWS" argument — the reason ZeroID accepts an
// arbitrary resource URI with no registry of known resource servers — applies to
// the `resource` claim, which is presence-gated and therefore restrict-only. It
// does NOT extend to `aud`, which is an accept/reject gate: swapping it from the
// issuer to a caller-chosen value is not a subset operation.
//
// So: a relying party MUST NOT use `aud` to decide whether to accept a ZeroID
// token. Pinning authjwt's optional Audience to your own identifier does not
// establish that the token was minted for you — any tenant principal can request
// that value. Authorize on `resource` (a binding ZeroID recorded), on `scopes`,
// and on the principal. If a future need genuinely requires an unforgeable
// audience, it needs the resource-server registry RFC 8707 §2's
// invalid_target-for-unknown-resource exists for, not a tweak here.
//
// A no-op when nothing was requested, so callers can apply it unconditionally
// and no grant's default issuance shape changes.
func bindResourceOnIssue(issue *IssueRequest, resources []string) {
	if len(resources) == 0 {
		return
	}
	issue.Audience = resources
	if issue.CustomClaims == nil {
		issue.CustomClaims = make(map[string]any, 1)
	}
	// Cloned rather than aliased. `resources` can arrive with cap > len (the
	// validator allocates cap for the pre-dedup count), so sharing one backing
	// array between `aud` and the `resource` claim means a later
	// append(issue.Audience, …) would write THROUGH into the claim Shield
	// enforces on — silently changing a binding with no error anywhere. Nothing
	// appends today; one word removes the whole class.
	issue.CustomClaims["resource"] = slices.Clone(resources)
}

// rejectUnsupportedResource fails a request that carries `resource` on a grant
// that does not yet honour it.
//
// Fail loud, never silently ignore. A caller that asks for a resource-bound
// token and receives an UNBOUND one has a token that works everywhere while
// believing it works in one place — the exact confusion INV-IDN-006 exists to
// prevent. RFC 8707 §2 specifies `invalid_target` for a resource the AS cannot
// honour, which covers "not on this grant" as well as "not a valid URI".
func rejectUnsupportedResource(req TokenRequest, grant string) error {
	if len(req.Resource) == 0 {
		return nil
	}
	return oauthBadRequest(oautherror.InvalidTarget,
		fmt.Sprintf("the resource parameter is not supported on the %s grant", grant))
}
