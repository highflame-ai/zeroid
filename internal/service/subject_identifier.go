package service

import (
	"errors"
	"fmt"
	"strings"
)

// RFC 9493 Subject Identifiers for Security Event Tokens.
//
// An ID-JAG may name its subject with a structured `sub_id` object rather than
// (or as well as) a bare `sub` string (zeroid#265). The object carries a
// `format` member that says how to read the rest:
//
//	{"format": "email",   "email": "alice@example.com"}
//	{"format": "opaque",  "id": "5be6d4a1"}
//	{"format": "iss_sub", "iss": "https://idp.example.com", "sub": "248289761001"}
//
// Why this is not simply "read one more claim". Three things have to be
// decided, and getting any of them wrong is a security bug rather than a
// missing feature:
//
//  1. WHICH ISSUER A SUBJECT BELONGS TO. `iss_sub` carries its own `iss`, and
//     that value is chosen by the IdP that signed the assertion. Left
//     unchecked it lets one trusted IdP name a subject in ANOTHER IdP's
//     namespace — the exact collision the issuer is there to prevent. So
//     `iss_sub.iss` must equal the verified issuer of the assertion carrying
//     it; anything else is refused.
//
//  2. WHAT STRING BECOMES THE PRINCIPAL. The value is used as user_id, which is
//     what Cedar policy matches on, so it must be the SAME string for the same
//     person whichever shape the IdP chose. The deployer's ClaimMapping stays
//     authoritative: when the mapped claim is present it is the principal, and
//     sub_id only supplies one when it is absent. `iss_sub` renders as its bare
//     `sub` — once item 1 holds, its issuer is the assertion's issuer, which the
//     minted token already records separately as `user_id_iss`. Encoding the
//     issuer into the principal as well would give one person two principals
//     (plain `sub` vs `iss_sub`) and silently re-key every user of an IdP the
//     day it starts emitting sub_id.
//
//     Known limit, accepted deliberately: the fill-in does not check that the
//     sub_id's KIND matches the mapped claim. A deployment mapping user_id to
//     `email` that receives an assertion with no `email` but an opaque sub_id
//     gets a non-email principal. Restricting fill-in to matching kinds would
//     refuse the #265 acceptance case itself (default `sub` mapping, email
//     sub_id, no `sub`). It fails safe rather than open — a principal in the
//     wrong namespace matches no email-keyed Cedar policy — and grants the IdP
//     nothing it could not already assert through the mapped claim.
//
//  3. WHAT COUNTS AS A DISAGREEMENT. Only a comparison between two identifiers
//     of the SAME kind can prove two principals are different: `iss_sub.sub`
//     against the plain `sub`, and an `email` sub_id against the plain `email`
//     claim. Those are refused when they differ — never merged, never ranked.
//     An `opaque` id has no plain counterpart, and comparing an opaque `sub`
//     with an email address proves nothing, so neither is treated as a
//     conflict. Treating "different kinds of identifier" as "different people"
//     would reject the most ordinary IdP shape there is (opaque `sub`, email
//     `sub_id`) while adding no security, since the principal is still read
//     from the mapped claim.
//
// Values are compared exactly. No case folding, no email normalisation and no
// whitespace trimming, on either side: each of those is a rule about when two
// different strings are one person, and that is not ours to decide on an IdP's
// behalf. A blank member is still rejected.
//
// Deliberately NOT implemented: the `aliases` format (a set of other subject
// identifiers). It exists precisely to name one subject several ways, so
// resolving it to a single principal means choosing among them — the ambiguity
// item 3 refuses. A document needing it can map a concrete format.
const (
	subjectIDFormatEmail   = "email"
	subjectIDFormatOpaque  = "opaque"
	subjectIDFormatIssSub  = "iss_sub"
	subjectIDFormatAliases = "aliases"
)

// subjectIdentifierClaim is the claim name RFC 9493 defines. Not routed through
// ClaimMapping: `sub_id` is named by the spec, the same footing as `resource` on
// the ID-JAG. ClaimMapping stays authoritative for where the PLAIN subject is
// read from, which is the mapping that varies between IdPs.
const subjectIdentifierClaim = "sub_id"

// errSubjectIdentifierUnsupported marks a sub_id that is well-formed as far as
// this server can tell, but whose format it does not resolve: the RFC 9493
// formats not implemented here (account, phone_number, did, uri), `aliases`,
// and any registry extension this server does not know.
//
// Distinct from a MALFORMED sub_id, and the distinction is what the caller
// acts on. A malformed one is a broken identity claim and always fails the
// redemption. An unsupported one only matters when it is needed: when the
// deployer's mapped claim is present it is the principal, a sub_id of a format
// we cannot read can neither supply nor contradict it, and refusing the whole
// assertion over it would reject any IdP that emits one of RFC 9493's other
// formats alongside an ordinary sub.
var errSubjectIdentifierUnsupported = errors.New("unsupported sub_id format")

// maxEchoedClaimLen bounds IdP-controlled strings (format names, issuers) that
// are echoed into error_description and logs.
const maxEchoedClaimLen = 128

// subjectIdentifier is a parsed, validated RFC 9493 `sub_id`.
type subjectIdentifier struct {
	format string

	// principal is the user_id this identifier supplies when the deployer's
	// mapped claim is absent from the assertion.
	principal string

	// counterpartClaim names the plain JWT claim that carries the SAME kind of
	// identifier, and counterpartValue is what this sub_id asserts it holds.
	// Empty for formats with no plain counterpart (opaque), which therefore
	// never conflict.
	counterpartClaim string
	counterpartValue string
}

// parseSubjectIdentifier reads the `sub_id` claim from a verified assertion.
//
// Returns (nil, nil) when the claim is absent — the ordinary case, where the
// caller uses the mapped plain subject. A present-but-MALFORMED sub_id is an
// error, not an absence: an IdP that meant to name a subject and produced
// something unreadable must not be treated as though it named nobody, because
// that silently falls through to whatever else is available.
//
// assertionIss is the verified `iss` of the assertion carrying the claim, used
// to pin `iss_sub` to its own issuer (see item 1 above).
//
// A format this server does not resolve returns an error wrapping
// errSubjectIdentifierUnsupported; see that sentinel for how callers treat it.
// A foreign-issuer iss_sub is NOT in that class — it is a security signal and
// always fatal.
func parseSubjectIdentifier(claims map[string]any, assertionIss string) (*subjectIdentifier, error) {
	raw, present := claims[subjectIdentifierClaim]
	if !present {
		return nil, nil
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a JSON object (RFC 9493 §3)", subjectIdentifierClaim)
	}

	format, _ := obj["format"].(string)
	if strings.TrimSpace(format) == "" {
		return nil, fmt.Errorf("%s is missing its required %q member", subjectIdentifierClaim, "format")
	}

	// Values are returned as written. Blank is rejected, but a value with
	// surrounding whitespace is NOT repaired — see the exact-comparison note
	// above; trimming here while the plain claims go untrimmed made one person
	// read as two.
	member := func(name string) (string, error) {
		v, _ := obj[name].(string)
		if strings.TrimSpace(v) == "" {
			return "", fmt.Errorf("%s format %q requires a non-empty %q member", subjectIdentifierClaim, format, name)
		}

		return v, nil
	}

	switch format {
	case subjectIDFormatEmail:
		email, err := member("email")
		if err != nil {
			return nil, err
		}

		return &subjectIdentifier{
			format:           format,
			principal:        email,
			counterpartClaim: "email",
			counterpartValue: email,
		}, nil

	case subjectIDFormatOpaque:
		id, err := member("id")
		if err != nil {
			return nil, err
		}

		return &subjectIdentifier{format: format, principal: id}, nil

	case subjectIDFormatIssSub:
		iss, err := member("iss")
		if err != nil {
			return nil, err
		}
		sub, err := member("sub")
		if err != nil {
			return nil, err
		}
		// Item 1. The IdP that signed this assertion may only name subjects
		// in its own namespace. Exact match against the VERIFIED issuer, not
		// the claim in the object, because the object is what is untrusted.
		if assertionIss == "" || iss != assertionIss {
			return nil, fmt.Errorf(
				"%s format %q names issuer %.*q, but the assertion was issued by %.*q; "+
					"an issuer may only identify its own subjects",
				subjectIdentifierClaim, format, maxEchoedClaimLen, iss, maxEchoedClaimLen, assertionIss)
		}

		return &subjectIdentifier{
			format:           format,
			principal:        sub,
			counterpartClaim: "sub",
			counterpartValue: sub,
		}, nil

	case subjectIDFormatAliases:
		// Its own message rather than the generic one: it IS a valid RFC 9493
		// format, so "unsupported" alone would read as an oversight somebody
		// should fix, when it is a decision. See the note above.
		return nil, fmt.Errorf(
			"%w: %s format %q names a subject several ways and cannot resolve to one principal; "+
				"publish a concrete format (%s, %s or %s)",
			errSubjectIdentifierUnsupported, subjectIdentifierClaim, format,
			subjectIDFormatEmail, subjectIDFormatOpaque, subjectIDFormatIssSub)

	default:
		return nil, fmt.Errorf(
			"%w: %s format %.*q is not supported (expected %s, %s or %s)",
			errSubjectIdentifierUnsupported, subjectIdentifierClaim, maxEchoedClaimLen, format,
			subjectIDFormatEmail, subjectIDFormatOpaque, subjectIDFormatIssSub)
	}
}

// conflictingClaim reports the plain claim, if any, that contradicts this
// sub_id — i.e. a claim of the same kind that is present in the assertion and
// holds a different value. Returns "" when nothing contradicts it.
//
// A counterpart that is present but not a string is a contradiction too: the
// assertion then carries two readings of the same identifier and only one of
// them can be the real one. A BLANK string is not: it identifies nobody, so it
// cannot name a different somebody. IdPs routinely emit `"email": ""` for users
// without one, and the same rule already rejects a blank member on the sub_id
// side.
func (s *subjectIdentifier) conflictingClaim(claims map[string]any) string {
	if s == nil || s.counterpartClaim == "" {
		return ""
	}
	raw, present := claims[s.counterpartClaim]
	if !present {
		return ""
	}
	v, ok := raw.(string)
	if !ok {
		return s.counterpartClaim
	}
	if strings.TrimSpace(v) != "" && v != s.counterpartValue {
		return s.counterpartClaim
	}

	return ""
}
