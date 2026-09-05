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
		// the absolute check alone is not enough to reject a hostless value for
		// the network schemes we actually bind against.
		if (u.Scheme == "http" || u.Scheme == "https") && u.Host == "" {
			return nil, oauthBadRequest(oautherror.InvalidTarget,
				fmt.Sprintf("resource %q must include a host", raw))
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
// refresh_token is deliberately absent and stays that way: a refresh continues
// an existing grant, so accepting a NEW binding there would let a client
// re-target a token it already holds, and re-binding is a fresh authorization
// decision that belongs at the original grant. A resource-bound request is
// issued no refresh token at all, so the case should not arise — this is the
// second lock on that door.
var resourceSupportedGrants = map[string]bool{
	// Populated as each grant's binding lands. Empty means every `resource`
	// request is refused with invalid_target — accepted-and-ignored is the one
	// outcome that must never happen.
}

func grantSupportsResource(grantType string) bool {
	return resourceSupportedGrants[grantType]
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
