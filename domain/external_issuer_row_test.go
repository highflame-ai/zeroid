package domain

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func validRow() *ExternalIssuer {
	e := &ExternalIssuer{
		AccountID:    "acct-1",
		Issuer:       "https://acme.okta.com",
		Kind:         IssuerKindPerson,
		JWKSURI:      "https://acme.okta.com/oauth2/v1/keys",
		Audiences:    []string{"https://zeroid.example.com"},
		ClaimMapping: map[string]string{"user_id": "sub"},
	}
	e.Normalize()
	return e
}

func issuerCode(err error) string {
	var ve *IssuerValidationError
	if errors.As(err, &ve) {
		return ve.Code
	}
	return ""
}

func TestExternalIssuerValidate(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*ExternalIssuer)
		v      IssuerValidation
		want   string
	}{
		{name: "valid", mutate: func(*ExternalIssuer) {}},
		{name: "ES384 (AWS STS)", mutate: func(e *ExternalIssuer) { e.Algorithms = []string{"RS256", "ES384"} }},
		{name: "ES512 unsupported", mutate: func(e *ExternalIssuer) { e.Algorithms = []string{"ES512"} }, want: "invalid_algorithms"},
		{name: "bad kind", mutate: func(e *ExternalIssuer) { e.Kind = "robot" }, want: "invalid_kind"},
		{name: "http issuer", mutate: func(e *ExternalIssuer) { e.Issuer = "http://acme.okta.com" }, want: "invalid_issuer"},
		{name: "http issuer allowed with private endpoints", mutate: func(e *ExternalIssuer) {
			e.Issuer = "http://mockidp:8080/okta"
			e.JWKSURI = "http://mockidp:8080/okta/oauth2/v1/keys"
		}, v: IssuerValidation{AllowHTTP: true}},
		{name: "issuer with query", mutate: func(e *ExternalIssuer) { e.Issuer = "https://acme.okta.com?x=1" }, want: "invalid_issuer"},
		{name: "templated issuer", mutate: func(e *ExternalIssuer) {
			e.Issuer = "https://login.microsoftonline.com/{tenantid}/v2.0"
		}, want: "invalid_issuer"},
		{name: "entra common as person", mutate: func(e *ExternalIssuer) {
			e.Issuer = "https://login.microsoftonline.com/common/v2.0"
		}, want: "invalid_issuer"},
		{name: "entra organizations as person", mutate: func(e *ExternalIssuer) {
			e.Issuer = "https://login.microsoftonline.com/organizations/v2.0"
		}, want: "invalid_issuer"},
		{name: "entra consumers as person", mutate: func(e *ExternalIssuer) {
			e.Issuer = "https://login.microsoftonline.com/consumers/v2.0"
		}, want: "invalid_issuer"},
		{name: "entra common as workload is refused too", mutate: func(e *ExternalIssuer) {
			e.Kind = IssuerKindWorkload
			e.Issuer = "https://login.microsoftonline.com/common/v2.0"
			e.ClaimConstraints = map[string][]string{"tid": {"t"}}
		}, want: "invalid_issuer"},
		{name: "GitHub Actions as a person issuer", mutate: func(e *ExternalIssuer) {
			e.Issuer = "https://token.actions.githubusercontent.com/"
		}, v: IssuerValidation{PinClaim: "repository_owner_id"}, want: "invalid_issuer"},
		{name: "GitHub Actions as a workload issuer", mutate: func(e *ExternalIssuer) {
			e.Kind = IssuerKindWorkload
			e.Issuer = "https://token.actions.githubusercontent.com"
			e.ClaimConstraints = map[string][]string{"repository_owner_id": {"123"}}
		}, v: IssuerValidation{PinClaim: "repository_owner_id"}},
		{name: "personal Microsoft accounts are unclaimable", mutate: func(e *ExternalIssuer) {
			e.Issuer = "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"
		}, want: "invalid_issuer"},
		{name: "http jwks_uri", mutate: func(e *ExternalIssuer) { e.JWKSURI = "http://acme.okta.com/keys" }, want: "invalid_jwks_uri"},
		{name: "person row without audiences (bindings admit client ids)", mutate: func(e *ExternalIssuer) { e.Audiences = nil }},
		{name: "workload row without audiences", mutate: func(e *ExternalIssuer) {
			e.Kind = IssuerKindWorkload
			e.Audiences = nil
		}, want: "invalid_audiences"},
		{name: "HS256", mutate: func(e *ExternalIssuer) { e.Algorithms = []string{"HS256"} }, want: "invalid_algorithms"},
		{name: "none alg", mutate: func(e *ExternalIssuer) { e.Algorithms = []string{"none"} }, want: "invalid_algorithms"},
		{name: "propagate groups", mutate: func(e *ExternalIssuer) { e.PropagateClaims = []string{"groups"} }, want: "invalid_propagate_claims"},
		{name: "unknown mapping key", mutate: func(e *ExternalIssuer) { e.ClaimMapping["sub"] = "sub" }, want: "invalid_claim_mapping"},
		{name: "groups mapping", mutate: func(e *ExternalIssuer) { e.ClaimMapping["groups"] = "groups" }},
		{name: "groups mapping to a renamed claim", mutate: func(e *ExternalIssuer) { e.ClaimMapping["groups"] = "member_of" }},
		{name: "groups mapping names no claim", mutate: func(e *ExternalIssuer) { e.ClaimMapping["groups"] = " " }, want: "invalid_claim_mapping"},
		{name: "groups mapping with surrounding whitespace", mutate: func(e *ExternalIssuer) { e.ClaimMapping["groups"] = " groups" }, want: "invalid_claim_mapping"},
		{name: "groups mapping with trailing whitespace", mutate: func(e *ExternalIssuer) { e.ClaimMapping["groups"] = "groups\t" }, want: "invalid_claim_mapping"},
		{name: "groups mapping on a workload row", mutate: func(e *ExternalIssuer) {
			e.Kind = IssuerKindWorkload
			e.ClaimMapping["groups"] = "groups"
		}, want: "invalid_claim_mapping"},
		{name: "groups mapping too long", mutate: func(e *ExternalIssuer) {
			e.ClaimMapping["groups"] = strings.Repeat("g", maxClaimNameBytes+1)
		}, want: "invalid_claim_mapping"},
		// ADR 0044 D16: an IdP claim never sets a token's role or capabilities.
		{name: "role is a reserved mapping key", mutate: func(e *ExternalIssuer) { e.ClaimMapping["role"] = "groups" }, want: "claim_mapping_reserved"},
		{name: "privilege_scope is a reserved mapping key", mutate: func(e *ExternalIssuer) { e.ClaimMapping["privilege_scope"] = "scp" }, want: "claim_mapping_reserved"},
		{name: "reserved on a workload row too", mutate: func(e *ExternalIssuer) {
			e.Kind = IssuerKindWorkload
			e.ClaimMapping = map[string]string{"role": "roles"}
		}, want: "claim_mapping_reserved"},
		{name: "role mapped to an over-long claim is still reserved", mutate: func(e *ExternalIssuer) {
			e.ClaimMapping["role"] = strings.Repeat("r", maxClaimNameBytes+1)
		}, want: "claim_mapping_reserved"},
		{name: "role mapped to a claim over 255 bytes is still reserved", mutate: func(e *ExternalIssuer) {
			e.ClaimMapping["role"] = strings.Repeat("r", 256)
		}, want: "claim_mapping_reserved"},
		{name: "a claim named role may feed another key", mutate: func(e *ExternalIssuer) { e.ClaimMapping["name"] = "role" }},
		{name: "person without user key", mutate: func(e *ExternalIssuer) { e.ClaimMapping = map[string]string{} }, want: "invalid_claim_mapping"},
		{name: "workload without user key", mutate: func(e *ExternalIssuer) {
			e.Kind = IssuerKindWorkload
			e.ClaimMapping = map[string]string{}
		}},
		{name: "constraint on aud pins nothing", mutate: func(e *ExternalIssuer) {
			e.ClaimConstraints = map[string][]string{"aud": {"x"}}
		}, want: "invalid_claim_constraints"},
		{name: "constraint on iss pins nothing", mutate: func(e *ExternalIssuer) {
			e.ClaimConstraints = map[string][]string{"iss": {"https://acme.okta.com"}}
		}, want: "invalid_claim_constraints"},
		{name: "empty constraint", mutate: func(e *ExternalIssuer) {
			e.ClaimConstraints = map[string][]string{"hd": {}}
		}, want: "invalid_claim_constraints"},
		{name: "shared without constraints", mutate: func(e *ExternalIssuer) {
			e.Issuer = "https://accounts.google.com"
		}, v: IssuerValidation{PinClaim: "hd"}, want: "shared_issuer_requires_constraints"},
		{name: "shared with constraints but not on its pinning claim", mutate: func(e *ExternalIssuer) {
			e.Issuer = "https://accounts.google.com"
			e.ClaimConstraints = map[string][]string{"email_verified": {"true"}}
		}, v: IssuerValidation{PinClaim: "hd"}, want: "shared_issuer_requires_constraints"},
		{name: "shared with constraints", mutate: func(e *ExternalIssuer) {
			e.Issuer = "https://accounts.google.com"
			e.ClaimConstraints = map[string][]string{"hd": {"acme.com"}}
		}, v: IssuerValidation{PinClaim: "hd"}},
		{name: "issuer too long", mutate: func(e *ExternalIssuer) {
			e.Issuer = "https://acme.okta.com/" + strings.Repeat("a", MaxIssuerURLBytes)
		}, want: "invalid_issuer"},
		{name: "constraint value too long", mutate: func(e *ExternalIssuer) {
			e.ClaimConstraints = map[string][]string{"hd": {strings.Repeat("a", 300)}}
		}, want: "invalid_claim_constraints"},
		{name: "too many audiences", mutate: func(e *ExternalIssuer) {
			for i := 0; i < 51; i++ {
				e.Audiences = append(e.Audiences, fmt.Sprintf("a%d", i))
			}
		}, want: "invalid_audiences"},
		{name: "token age too long", mutate: func(e *ExternalIssuer) { e.MaxTokenAgeSeconds = 7200 }, want: "invalid_max_token_age"},
		{name: "jwks ttl too short", mutate: func(e *ExternalIssuer) { e.JWKSCacheTTLSeconds = 5 }, want: "invalid_jwks_cache_ttl"},
		{name: "connector without ref", mutate: func(e *ExternalIssuer) { e.Source = IssuerSourceConnector }, want: "invalid_source"},
		{name: "admin with ref", mutate: func(e *ExternalIssuer) { e.SourceRef = "conn-1" }, want: "invalid_source"},
		{name: "config source is not writable", mutate: func(e *ExternalIssuer) { e.Source = IssuerSourceConfig }, want: "invalid_source"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := validRow()
			tc.mutate(e)
			err := e.Validate(tc.v)
			if got := issuerCode(err); got != tc.want {
				t.Fatalf("code = %q (err %v), want %q", got, err, tc.want)
			}
		})
	}
}

func TestExternalIssuerUniquenessKey(t *testing.T) {
	a := validRow()
	a.ClaimConstraints = map[string][]string{"hd": {"acme", "beta"}, "groups": {"x"}}
	b := validRow()
	b.ClaimConstraints = map[string][]string{"hd": {"beta", "acme"}, "groups": {"y"}}
	if a.UniquenessKey("") != "" {
		t.Fatal("a customer-unique issuer has an empty key, so one row per kind")
	}
	if a.UniquenessKey("hd") == "" || a.UniquenessKey("hd") != b.UniquenessKey("hd") {
		t.Fatal("the key is the pinning claim's values, in any order; other constraints do not count")
	}
	b.ClaimConstraints["hd"] = []string{"acme"}
	if a.UniquenessKey("hd") == b.UniquenessKey("hd") {
		t.Fatal("different pins give different keys")
	}
}

func TestExternalIssuerConstraintsMatch(t *testing.T) {
	e := validRow()
	e.ClaimConstraints = map[string][]string{"tid": {"t1"}, "groups": {"agents"}}
	if !e.ConstraintsMatch(map[string]any{"tid": "t1", "groups": []any{"x", "agents"}}, "") {
		t.Fatal("matching claims must match")
	}
	if e.ConstraintsMatch(map[string]any{"tid": "t2", "groups": []any{"agents"}}, "") {
		t.Fatal("a wrong value must not match")
	}
	if e.ConstraintsMatch(map[string]any{"groups": []any{"agents"}}, "") {
		t.Fatal("a missing claim must not match")
	}
	if e.ConstraintsMatch(map[string]any{"tid": 1, "groups": "agents"}, "") {
		t.Fatal("a non-string claim must not match")
	}
	if !e.ConstraintsMatch(map[string]any{"tid": "t1", "groups": []any{"agents"}}, "tid") {
		t.Fatal("a scalar pin matches")
	}
	if e.ConstraintsMatch(map[string]any{"tid": []any{"t1", "t2"}, "groups": []any{"agents"}}, "tid") {
		t.Fatal("an array in the pinning claim must not match: it could name several customers")
	}
}

func TestValidateSharedIssuers(t *testing.T) {
	if err := ValidateSharedIssuers(DefaultSharedIssuers, false); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]SharedIssuer{
		{{Issuer: "https://x"}},
		{{Issuer: "https://x", PinClaim: "aud"}},
		{{Issuer: "http://x", PinClaim: "hd"}},
	} {
		if ValidateSharedIssuers(bad, false) == nil {
			t.Fatalf("%v must be refused", bad)
		}
	}
	local := []SharedIssuer{{Issuer: "http://mockidp:8080/google", PinClaim: "hd"}}
	if err := ValidateSharedIssuers(local, true); err != nil {
		t.Fatalf("with private endpoints allowed an http shared issuer is accepted: %v", err)
	}
	if ValidateSharedIssuers([]SharedIssuer{{Issuer: "http://x"}}, true) == nil {
		t.Fatal("allowHTTP never waives the pinning claim")
	}
}

func TestApplyIssuerPreset(t *testing.T) {
	const tid = "11111111-2222-3333-4444-555555555555"
	t.Run("entra fills keys, oid and the tid pin", func(t *testing.T) {
		e := &ExternalIssuer{Kind: IssuerKindPerson, Issuer: "https://login.microsoftonline.com/" + tid + "/v2.0", Audiences: []string{"app"}}
		if err := ApplyIssuerPreset(e, IssuerPresetEntra); err != nil {
			t.Fatal(err)
		}
		if e.JWKSURI != "" {
			t.Fatalf("jwks_uri = %s; it comes from discovery, never a preset", e.JWKSURI)
		}
		if e.ClaimMapping["user_id"] != "oid" || e.ClaimMapping["email_verified"] != "xms_edov" {
			t.Fatalf("mapping = %v", e.ClaimMapping)
		}
		if got := e.ClaimConstraints["tid"]; len(got) != 1 || got[0] != tid {
			t.Fatalf("tid constraint = %v", got)
		}
		e.Normalize()
		if err := e.Validate(IssuerValidation{JWKSURIPending: true}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("entra pins the identity claims (nOAuth)", func(t *testing.T) {
		for _, m := range []map[string]string{{"user_id": "preferred_username"}, {"email": "upn"}, {"email_verified": "email_verified"}} {
			e := &ExternalIssuer{Issuer: "https://login.microsoftonline.com/" + tid + "/v2.0", ClaimMapping: m}
			if got := issuerCode(ApplyIssuerPreset(e, IssuerPresetEntra)); got != "invalid_claim_mapping" {
				t.Fatalf("%v: code = %q", m, got)
			}
		}
		e := &ExternalIssuer{Issuer: "https://login.microsoftonline.com/" + tid + "/v2.0", ClaimMapping: map[string]string{"user_id": "oid", "name": "given_name"}}
		if err := ApplyIssuerPreset(e, IssuerPresetEntra); err != nil || e.ClaimMapping["name"] != "given_name" {
			t.Fatalf("the pinned value itself and other keys are accepted: %v %v", err, e.ClaimMapping)
		}
	})
	t.Run("okta pins the identity claims", func(t *testing.T) {
		e := &ExternalIssuer{Issuer: "https://acme.okta.com", ClaimMapping: map[string]string{"user_id": "email"}}
		if got := issuerCode(ApplyIssuerPreset(e, IssuerPresetOkta)); got != "invalid_claim_mapping" {
			t.Fatalf("code = %q", got)
		}
	})
	for _, iss := range []string{
		"https://login.microsoftonline.com/common/v2.0",
		"https://login.microsoftonline.com/{tenantid}/v2.0",
		"https://login.microsoftonline.com/" + tid,
		"https://sts.windows.net/" + tid + "/",
	} {
		t.Run("entra refuses "+iss, func(t *testing.T) {
			e := &ExternalIssuer{Issuer: iss}
			if got := issuerCode(ApplyIssuerPreset(e, IssuerPresetEntra)); got != "invalid_issuer" {
				t.Fatalf("code = %q", got)
			}
		})
	}
	t.Run("entra refuses a conflicting tid pin", func(t *testing.T) {
		e := &ExternalIssuer{Issuer: "https://login.microsoftonline.com/" + tid + "/v2.0",
			ClaimConstraints: map[string][]string{"tid": {"other"}}}
		if got := issuerCode(ApplyIssuerPreset(e, IssuerPresetEntra)); got != "invalid_claim_constraints" {
			t.Fatalf("code = %q", got)
		}
	})
	t.Run("okta org server", func(t *testing.T) {
		e := &ExternalIssuer{Kind: IssuerKindPerson, Issuer: "https://acme.okta.com/"}
		if err := ApplyIssuerPreset(e, IssuerPresetOkta); err != nil {
			t.Fatal(err)
		}
		if e.Issuer != "https://acme.okta.com" || e.JWKSURI != "" {
			t.Fatalf("issuer %s jwks %s", e.Issuer, e.JWKSURI)
		}
		if len(e.Audiences) != 0 {
			t.Fatalf("audiences = %v; an ID-JAG's audience is ZeroID's issuer, never a row value", e.Audiences)
		}
		if e.ClaimMapping["user_id"] != "sub" {
			t.Fatal("Okta's user key is sub")
		}
	})
	t.Run("okta custom server", func(t *testing.T) {
		e := &ExternalIssuer{Issuer: "https://acme.okta.com/oauth2/aus1"}
		if err := ApplyIssuerPreset(e, IssuerPresetOkta); err != nil {
			t.Fatal(err)
		}
		if e.JWKSURI != "" {
			t.Fatalf("jwks %s", e.JWKSURI)
		}
	})
	t.Run("okta refuses a deeper path", func(t *testing.T) {
		if got := issuerCode(ApplyIssuerPreset(&ExternalIssuer{Issuer: "https://acme.okta.com/oauth2/aus1/extra"}, IssuerPresetOkta)); got != "invalid_issuer" {
			t.Fatalf("code = %q", got)
		}
	})
	t.Run("presets fill groups when unset", func(t *testing.T) {
		for preset, iss := range map[string]string{
			IssuerPresetEntra: "https://login.microsoftonline.com/" + tid + "/v2.0",
			IssuerPresetOkta:  "https://acme.okta.com",
		} {
			e := &ExternalIssuer{Kind: IssuerKindPerson, Issuer: iss}
			if err := ApplyIssuerPreset(e, preset); err != nil {
				t.Fatalf("%s: %v", preset, err)
			}
			if e.ClaimMapping["groups"] != "groups" {
				t.Fatalf("%s: claim_mapping.groups = %q, want groups", preset, e.ClaimMapping["groups"])
			}
		}
	})
	t.Run("presets keep a groups claim the admin set", func(t *testing.T) {
		for preset, iss := range map[string]string{
			IssuerPresetEntra: "https://login.microsoftonline.com/" + tid + "/v2.0",
			IssuerPresetOkta:  "https://acme.okta.com",
		} {
			e := &ExternalIssuer{Kind: IssuerKindPerson, Issuer: iss, ClaimMapping: map[string]string{"groups": "member_of"}}
			if err := ApplyIssuerPreset(e, preset); err != nil {
				t.Fatalf("%s: %v", preset, err)
			}
			if e.ClaimMapping["groups"] != "member_of" {
				t.Fatalf("%s: claim_mapping.groups = %q, want the admin's member_of", preset, e.ClaimMapping["groups"])
			}
		}
	})
	t.Run("an explicit empty groups turns groups off: no preset fill, stored as no mapping", func(t *testing.T) {
		for preset, iss := range map[string]string{
			IssuerPresetEntra: "https://login.microsoftonline.com/" + tid + "/v2.0",
			IssuerPresetOkta:  "https://acme.okta.com",
		} {
			for _, empty := range []string{"", " "} {
				e := &ExternalIssuer{Kind: IssuerKindPerson, Issuer: iss, ClaimMapping: map[string]string{"groups": empty}}
				if err := ApplyIssuerPreset(e, preset); err != nil {
					t.Fatalf("%s: %v", preset, err)
				}
				e.Normalize()
				if g, set := e.ClaimMapping["groups"]; set {
					t.Fatalf("%s: claim_mapping.groups = %q, want no mapping", preset, g)
				}
				if err := e.Validate(IssuerValidation{JWKSURIPending: true}); err != nil {
					t.Fatalf("%s: %v", preset, err)
				}
			}
		}
	})
	t.Run("unknown preset", func(t *testing.T) {
		if got := issuerCode(ApplyIssuerPreset(&ExternalIssuer{}, "auth0")); got != "invalid_preset" {
			t.Fatalf("code = %q", got)
		}
	})
}

func TestExternalIssuerConfigAudienceAndKind(t *testing.T) {
	c := ExternalIssuerConfig{Audience: "a", Audiences: []string{"b", "a", ""}}
	if got := c.AudienceList(); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("AudienceList = %v", got)
	}
	if c.EffectiveKind() != IssuerKindPerson {
		t.Fatal("a static issuer defaults to person")
	}
	c = ExternalIssuerConfig{Issuer: "https://i", JWKSURI: "https://i/k", Audiences: []string{"x"},
		ClaimMapping: map[string]string{"user_id": "sub"}, AllowedAccounts: []string{"a"}, Kind: "robot"}
	if err := c.Validate(); err == nil {
		t.Fatal("an unknown kind is refused")
	}
	c.Kind = IssuerKindWorkload
	if err := c.Validate(); err != nil {
		t.Fatalf("audiences alone satisfy the audience requirement: %v", err)
	}
}

// A reserved key wins over any other claim_mapping fault, whatever order the
// map iterates in (ADR 0044 D16).
func TestExternalIssuerValidate_ReservedKeyCodeIsDeterministic(t *testing.T) {
	for i := 0; i < 500; i++ {
		e := validRow()
		e.ClaimMapping = map[string]string{
			"user_id": "sub", "role": "groups", "sub": "x", "zzz": "y", "aaa": "z",
			"name": strings.Repeat("n", maxClaimNameBytes+1), "email": " ",
		}
		err := e.Validate(IssuerValidation{})
		if got := issuerCode(err); got != "claim_mapping_reserved" {
			t.Fatalf("iteration %d: code = %q (err %v), want claim_mapping_reserved", i, got, err)
		}
		if !strings.Contains(err.Error(), `"role"`) {
			t.Fatalf("iteration %d: %v does not name role", i, err)
		}
	}
}

func TestReservedMappingKeysIn(t *testing.T) {
	got := ReservedMappingKeysIn(map[string]string{"privilege_scope": "a", "user_id": "sub", "role": "b"})
	if fmt.Sprint(got) != "[role privilege_scope]" {
		t.Fatalf("got %v, want [role privilege_scope] in fixed order", got)
	}
	if got := ReservedMappingKeysIn(map[string]string{"user_id": "sub"}); len(got) != 0 {
		t.Fatalf("got %v, want none", got)
	}
}
