package service

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/rs/zerolog/log"
)

// Limits on the groups a person grant copies from an IdP token into the
// issued token's `groups` claim (RFC 9068 §2.2.3.1). They keep a token from
// growing without bound with the person's directory. Above any of them the
// whole claim is dropped, never truncated: a partial list would look
// complete to a resource server, while an absent one says "unknown".
const (
	// MaxPersonGroups is the most groups a token carries, counted after
	// unusable entries are skipped and duplicates collapse. Okta caps its
	// groups claim at 100; Entra switches to an overage indicator above 200
	// in a JWT.
	MaxPersonGroups = 100
	// MaxPersonGroupsRawEntries bounds the entries read from the IdP's claim
	// at all, before any filtering, so parsing work stays bounded.
	MaxPersonGroupsRawEntries = 1000
	// MaxPersonGroupLength is the longest single group name, in bytes.
	MaxPersonGroupLength = 256
	// MaxPersonGroupsBytes bounds the sum of the group names, in bytes.
	MaxPersonGroupsBytes = 8192
)

// extractPersonGroups reads the groups an issuer's claim_mapping.groups names
// from a verified person token. It never fails the grant: an unmapped or
// absent claim yields nil silently, and a malformed, oversized or overage
// claim yields nil with a warning naming the issuer and the reason (never
// the values, which are directory data).
//
// Accepted shapes are a JSON array of strings and a single string (one
// group). Entries that are not strings or not usable names (validGroupName)
// are skipped, and duplicates collapse, in the IdP's order. Names are kept
// byte for byte: no trimming, case folding or Unicode normalization, because
// a policy must match exactly what the IdP sends.
//
// Entra omits the list when a person is in too many groups and names it in
// _claim_names instead (a distributed claim, OIDC Core §5.6.2), or sets
// hasgroups on the implicit flow. Both read as no groups.
func extractPersonGroups(claims map[string]any, claim, issuer string) []string {
	if claim == "" {
		return nil
	}
	v, present := claims[claim]
	if !present {
		if groupsOverage(claims, claim) {
			warnGroupsDropped(issuer, claim, "overage: the IdP sent a reference instead of the list")
		}
		return nil
	}
	var raw []any
	switch tv := v.(type) {
	case string:
		raw = []any{tv}
	case []string:
		raw = make([]any, len(tv))
		for i, s := range tv {
			raw[i] = s
		}
	case []any:
		raw = tv
	default:
		warnGroupsDropped(issuer, claim, "not an array of strings or a string")
		return nil
	}
	if len(raw) > MaxPersonGroupsRawEntries {
		warnGroupsDropped(issuer, claim, "too many entries")
		return nil
	}
	out := make([]string, 0, min(len(raw), MaxPersonGroups))
	seen := make(map[string]struct{}, len(raw))
	total, skipped := 0, 0
	for _, e := range raw {
		s, ok := e.(string)
		if !ok || !validGroupName(s) {
			skipped++
			continue
		}
		if len(s) > MaxPersonGroupLength {
			warnGroupsDropped(issuer, claim, "a group name is too long")
			return nil
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		if len(out) == MaxPersonGroups {
			warnGroupsDropped(issuer, claim, "too many groups")
			return nil
		}
		total += len(s)
		if total > MaxPersonGroupsBytes {
			warnGroupsDropped(issuer, claim, "the groups are too large")
			return nil
		}
		out = append(out, s)
	}
	if skipped > 0 {
		log.Warn().Str("upstream_iss", issuer).Str("claim", claim).Int("skipped", skipped).
			Msg("person token groups: skipped entries that are not usable group names")
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// blankOrReplacementRune reports the runes that are neither controls nor
// separators but still make a name unusable: U+FFFD, which JSON decoding
// substitutes for invalid UTF-8 (so two different malformed names would
// collapse into one group), and the Hangul fillers, which render blank.
func blankOrReplacementRune(r rune) bool {
	switch r {
	case utf8.RuneError, '\u3164', '\u115f', '\u1160', '\uffa0':
		return true
	}
	return false
}

// validGroupName reports whether s is a group name a token may carry: valid
// UTF-8, not empty or blank, no leading or trailing whitespace, no control
// or format characters (the floor sanitizePrincipalAttribute applies to the
// display attributes), and no space separator other than U+0020 (a line or
// paragraph separator, or a no-break or ideographic space, would make two
// names that look the same compare unequal), and no replacement character
// or blank-rendering filler (blankOrReplacementRune).
func validGroupName(s string) bool {
	if !utf8.ValidString(s) || strings.TrimSpace(s) == "" || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || (unicode.Is(unicode.Z, r) && r != ' ') || blankOrReplacementRune(r) {
			return false
		}
	}
	return true
}

// groupsOverage reports whether claims signal that the IdP left the groups
// list out because it was too long: a _claim_names entry for claim, or
// Entra's hasgroups.
func groupsOverage(claims map[string]any, claim string) bool {
	if names, ok := claims["_claim_names"].(map[string]any); ok {
		if _, ok := names[claim]; ok {
			return true
		}
	}
	has, _ := claims["hasgroups"].(bool)
	return has
}

func warnGroupsDropped(issuer, claim, reason string) {
	log.Warn().Str("upstream_iss", issuer).Str("claim", claim).Str("reason", reason).
		Msg("person token groups dropped; the issued token carries no groups claim")
}

// parentGroups reads the `groups` claim of a verified ZeroID token, the
// parent of a token exchange, so the person's groups travel down the chain
// with sub. ZeroID wrote the claim within the limits above; they are
// re-applied anyway, so a chain can never carry more than a root could.
func parentGroups(parent jwt.Token) []string {
	var raw []any
	if v, err := jwt.Get[[]any](parent, "groups"); err == nil {
		raw = v
	} else if v, err := jwt.Get[[]string](parent, "groups"); err == nil {
		for _, s := range v {
			raw = append(raw, s)
		}
	} else {
		return nil
	}
	return extractPersonGroups(map[string]any{"groups": raw}, "groups", "zeroid:parent")
}
