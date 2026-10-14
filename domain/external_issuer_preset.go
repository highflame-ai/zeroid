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

// ApplyIssuerPreset fills e from preset. zeroidIssuer is this server's
// issuer, the audience of an Okta ID-JAG.
func ApplyIssuerPreset(e *ExternalIssuer, preset, zeroidIssuer string) error {
	switch preset {
	case "", "generic":
		return nil
	case IssuerPresetEntra:
		return applyEntraPreset(e)
	case IssuerPresetOkta:
		return applyOktaPreset(e, zeroidIssuer)
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
	if e.JWKSURI == "" {
		e.JWKSURI = "https://" + entraHost + "/" + tid + "/discovery/v2.0/keys"
	}
	if len(e.Algorithms) == 0 {
		e.Algorithms = []string{"RS256"}
	}
	// oid, not sub: Entra's sub is pairwise per application.
	fillMapping(e, map[string]string{"user_id": "oid", "email": "email", "email_verified": "xms_edov", "name": "name"})
	if e.ClaimConstraints == nil {
		e.ClaimConstraints = map[string][]string{}
	}
	if got, set := e.ClaimConstraints["tid"]; set && !slices.Equal(got, []string{tid}) {
		return issuerInvalid("invalid_claim_constraints", "claim_constraints.tid must be the issuer's tenant id")
	}
	e.ClaimConstraints["tid"] = []string{tid}
	return nil
}

func applyOktaPreset(e *ExternalIssuer, zeroidIssuer string) error {
	iss := strings.TrimRight(strings.TrimSpace(e.Issuer), "/")
	u, err := url.Parse(iss)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return issuerInvalid("invalid_issuer", "an Okta issuer is https://<org>.okta.com or https://<org>.okta.com/oauth2/<server-id>")
	}
	e.Issuer = iss
	if e.JWKSURI == "" {
		switch {
		case u.Path == "":
			e.JWKSURI = iss + "/oauth2/v1/keys"
		case strings.HasPrefix(u.Path, "/oauth2/") && strings.Count(u.Path, "/") == 2:
			e.JWKSURI = iss + "/v1/keys"
		default:
			return issuerInvalid("invalid_issuer", "an Okta issuer is https://<org>.okta.com or https://<org>.okta.com/oauth2/<server-id>")
		}
	}
	if len(e.Algorithms) == 0 {
		e.Algorithms = []string{"RS256"}
	}
	if len(e.Audiences) == 0 && zeroidIssuer != "" && e.Kind == IssuerKindPerson {
		e.Audiences = []string{zeroidIssuer}
	}
	fillMapping(e, map[string]string{"user_id": "sub", "email": "email", "email_verified": "email_verified", "name": "name"})
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
