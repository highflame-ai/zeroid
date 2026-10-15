package domain

import (
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// Issuer presets fill the fields an IdP fixes, so an admin supplies only the
// issuer and the audiences. They never override a value the request set,
// except that the Entra preset always pins the tid claim.
const (
	IssuerPresetEntra = "entra"
	IssuerPresetOkta  = "okta"
)

var entraIssuerPath = regexp.MustCompile(`^/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/v2\.0$`)

// ApplyIssuerPreset fills e from preset.
func ApplyIssuerPreset(e *ExternalIssuer, preset string) error {
	switch preset {
	case "", "generic":
		return nil
	case IssuerPresetEntra:
		return applyEntraPreset(e)
	case IssuerPresetOkta:
		return applyOktaPreset(e)
	}
	return issuerInvalid("invalid_preset", "preset must be entra, okta or generic")
}

// EntraTenantID returns the tenant id of a single-tenant Entra v2.0 issuer.
func EntraTenantID(iss string) (string, bool) {
	u, err := url.Parse(iss)
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Host, entraHost) {
		return "", false
	}
	m := entraIssuerPath.FindStringSubmatch(u.Path)
	if m == nil {
		return "", false
	}
	return strings.ToLower(m[1]), true
}

func applyEntraPreset(e *ExternalIssuer) error {
	tid, ok := EntraTenantID(strings.TrimSpace(e.Issuer))
	if !ok {
		return issuerInvalid("invalid_issuer",
			"an Entra issuer is https://login.microsoftonline.com/<tenant-id>/v2.0, with the tenant's GUID")
	}
	if len(e.Algorithms) == 0 {
		e.Algorithms = []string{"RS256"}
	}
	// oid, not sub: Entra's sub is pairwise per application. The identity
	// claims are pinned: a user-settable claim there would let an IdP user
	// take over another person's link (nOAuth).
	if err := pinMapping(e, map[string]string{"user_id": "oid", "email": "email", "email_verified": "xms_edov"}); err != nil {
		return err
	}
	fillMapping(e, map[string]string{"name": "name"})
	if e.ClaimConstraints == nil {
		e.ClaimConstraints = map[string][]string{}
	}
	if got, set := e.ClaimConstraints["tid"]; set && !slices.Equal(got, []string{tid}) {
		return issuerInvalid("invalid_claim_constraints", "claim_constraints.tid must be the issuer's tenant id")
	}
	e.ClaimConstraints["tid"] = []string{tid}
	return nil
}

func applyOktaPreset(e *ExternalIssuer) error {
	iss := strings.TrimRight(strings.TrimSpace(e.Issuer), "/")
	u, err := url.Parse(iss)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return issuerInvalid("invalid_issuer", "an Okta issuer is https://<org>.okta.com or https://<org>.okta.com/oauth2/<server-id>")
	}
	e.Issuer = iss
	if u.Path != "" && (!strings.HasPrefix(u.Path, "/oauth2/") || strings.Count(u.Path, "/") != 2) {
		return issuerInvalid("invalid_issuer", "an Okta issuer is https://<org>.okta.com or https://<org>.okta.com/oauth2/<server-id>")
	}
	if len(e.Algorithms) == 0 {
		e.Algorithms = []string{"RS256"}
	}
	if err := pinMapping(e, map[string]string{"user_id": "sub", "email": "email", "email_verified": "email_verified"}); err != nil {
		return err
	}
	fillMapping(e, map[string]string{"name": "name"})
	return nil
}

// IdentityMappingKeys decide who a token's person is: the user key, and the
// email and its verification that first-sight linking trusts. They are
// fixed at create (ADR 0042 D5a).
var IdentityMappingKeys = []string{"user_id", "email", "email_verified"}

// pinMapping sets keys a preset fixes, refusing a request that names
// another claim for one of them.
func pinMapping(e *ExternalIssuer, pinned map[string]string) error {
	if e.ClaimMapping == nil {
		e.ClaimMapping = map[string]string{}
	}
	for k, v := range pinned {
		if got, set := e.ClaimMapping[k]; set && got != v {
			return issuerInvalid("invalid_claim_mapping", "this preset fixes claim_mapping.%s to %q", k, v)
		}
		e.ClaimMapping[k] = v
	}
	return nil
}

func fillMapping(e *ExternalIssuer, defaults map[string]string) {
	if e.ClaimMapping == nil {
		e.ClaimMapping = map[string]string{}
	}
	for k, v := range defaults {
		if _, set := e.ClaimMapping[k]; !set {
			e.ClaimMapping[k] = v
		}
	}
}
