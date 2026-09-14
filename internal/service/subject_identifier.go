package service

import (
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
// Why this is not simply "read one more claim". Two things have to be decided,
// and getting either wrong is a security bug rather than a missing feature:
//
//  1. WHAT STRING BECOMES THE PRINCIPAL. The value is used as user_id, which is
//     what Cedar policy matches on, so two different people must never collapse
//     to one string. `iss_sub` is the case that makes this concrete: taking its
//     `sub` alone would merge subject "1001" at IdP A with subject "1001" at
//     IdP B. It is rendered as a composite that keeps the issuer, so distinct
//     subjects stay distinct.
//
//  2. WHAT HAPPENS WHEN `sub` AND `sub_id` DISAGREE. They are refused, not
//     merged and not silently ranked. An assertion naming two different
//     principals is not a preference question — it is either a broken IdP or an
//     attempt to have one identity read by the check and another by the mint,
//     and there is no reading of it that is safe to act on.
//
// Deliberately NOT implemented: the `aliases` format (a set of other subject
// identifiers). It exists precisely to name one subject several ways, so
// resolving it to a single principal means choosing among them — the same
// ambiguity item 2 refuses. A document needing it can map a concrete format.
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

// resolveSubjectIdentifier renders an RFC 9493 `sub_id` object as the stable
// principal string used for user_id.
//
// Returns ("", false) when the claim is absent or is not an object — absent is
// the ordinary case and the caller falls back to the mapped plain subject. A
// present-but-MALFORMED sub_id is an error, not an absence: an IdP that meant to
// name a subject and produced something unreadable must not be treated as
// though it named nobody, because that silently falls through to whatever else
// is available.
func resolveSubjectIdentifier(claims map[string]any) (string, bool, error) {
	raw, present := claims[subjectIdentifierClaim]
	if !present {
		return "", false, nil
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		return "", false, fmt.Errorf("%s must be a JSON object (RFC 9493 §3)", subjectIdentifierClaim)
	}

	format, _ := obj["format"].(string)
	format = strings.TrimSpace(format)
	if format == "" {
		return "", false, fmt.Errorf("%s is missing its required %q member", subjectIdentifierClaim, "format")
	}

	member := func(name string) (string, error) {
		v, _ := obj[name].(string)
		if v = strings.TrimSpace(v); v == "" {
			return "", fmt.Errorf("%s format %q requires a non-empty %q member", subjectIdentifierClaim, format, name)
		}

		return v, nil
	}

	switch format {
	case subjectIDFormatEmail:
		email, err := member("email")
		if err != nil {
			return "", false, err
		}

		return email, true, nil

	case subjectIDFormatOpaque:
		id, err := member("id")
		if err != nil {
			return "", false, err
		}

		return id, true, nil

	case subjectIDFormatIssSub:
		// Composite, and this is the whole reason the function exists rather
		// than a switch inline at the call site: `sub` alone is unique only
		// WITHIN an issuer, so dropping `iss` would merge distinct people from
		// different IdPs onto one principal. The separator is one this server
		// controls and neither member can contain unescaped — `iss` is a URL and
		// `sub` is opaque — so the rendering cannot be made ambiguous by a
		// hostile IdP choosing a colliding value.
		iss, err := member("iss")
		if err != nil {
			return "", false, err
		}
		sub, err := member("sub")
		if err != nil {
			return "", false, err
		}

		return iss + "#" + sub, true, nil

	case subjectIDFormatAliases:
		// Refused with its own message rather than the generic one: it IS a
		// valid RFC 9493 format, so "unsupported" would read as an oversight
		// somebody should fix, when it is a decision. See the note above.
		return "", false, fmt.Errorf(
			"%s format %q names a subject several ways and cannot resolve to one principal; "+
				"publish a concrete format (%s, %s or %s)",
			subjectIdentifierClaim, format,
			subjectIDFormatEmail, subjectIDFormatOpaque, subjectIDFormatIssSub)

	default:
		return "", false, fmt.Errorf(
			"%s format %q is not supported (expected %s, %s or %s)",
			subjectIdentifierClaim, format,
			subjectIDFormatEmail, subjectIDFormatOpaque, subjectIDFormatIssSub)
	}
}

// subjectIdentifierConflicts reports whether a resolved sub_id names a different
// principal from the mapped plain subject.
//
// Only meaningful when both are present. The comparison is deliberately exact
// rather than clever: no case folding, no email normalisation, no treating an
// `iss_sub` composite as "containing" the plain sub. Every one of those would be
// a rule about when two different strings may be treated as one person, which is
// exactly the judgement this refuses to make on an IdP's behalf.
func subjectIdentifierConflicts(plainSub, fromSubID string) bool {
	return plainSub != "" && fromSubID != "" && plainSub != fromSubID
}
