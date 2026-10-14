package domain

import (
	"errors"
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
		{name: "entra common as workload with constraints is allowed", mutate: func(e *ExternalIssuer) {
			e.Kind = IssuerKindWorkload
			e.Issuer = "https://login.microsoftonline.com/common/v2.0"
			e.ClaimConstraints = map[string][]string{"tid": {"t"}}
		}, v: IssuerValidation{Shared: true}},
		{name: "GitHub Actions as a person issuer", mutate: func(e *ExternalIssuer) {
			e.Issuer = "https://token.actions.githubusercontent.com/"
		}, v: IssuerValidation{Shared: true}, want: "invalid_issuer"},
		{name: "GitHub Actions as a workload issuer", mutate: func(e *ExternalIssuer) {
			e.Kind = IssuerKindWorkload
			e.Issuer = "https://token.actions.githubusercontent.com"
			e.ClaimConstraints = map[string][]string{"repository_owner": {"acme"}}
		}, v: IssuerValidation{Shared: true}},
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
		}, v: IssuerValidation{Shared: true}, want: "shared_issuer_requires_constraints"},
		{name: "shared with constraints", mutate: func(e *ExternalIssuer) {
			e.Issuer = "https://accounts.google.com"
			e.ClaimConstraints = map[string][]string{"hd": {"acme.com"}}
		}, v: IssuerValidation{Shared: true}},
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
	a.ClaimConstraints = map[string][]string{"repository_owner": {"acme", "beta"}, "aud": {"x"}}
	b := validRow()
	b.ClaimConstraints = map[string][]string{"aud": {"x"}, "repository_owner": {"beta", "acme"}}
	if a.UniquenessKey(false) != "" {
		t.Fatal("a customer-unique issuer has an empty key, so one row per kind")
	}
	if a.UniquenessKey(true) == "" || a.UniquenessKey(true) != b.UniquenessKey(true) {
		t.Fatal("equal constraints in any order give the same key")
	}
	b.ClaimConstraints["repository_owner"] = []string{"acme"}
	if a.UniquenessKey(true) == b.UniquenessKey(true) {
		t.Fatal("different constraints give different keys")
	}
}

func TestExternalIssuerConstraintsMatch(t *testing.T) {
	e := validRow()
	e.ClaimConstraints = map[string][]string{"tid": {"t1"}, "groups": {"agents"}}
	if !e.ConstraintsMatch(map[string]any{"tid": "t1", "groups": []any{"x", "agents"}}) {
		t.Fatal("matching claims must match")
	}
	if e.ConstraintsMatch(map[string]any{"tid": "t2", "groups": []any{"agents"}}) {
		t.Fatal("a wrong value must not match")
	}
	if e.ConstraintsMatch(map[string]any{"groups": []any{"agents"}}) {
		t.Fatal("a missing claim must not match")
	}
	if e.ConstraintsMatch(map[string]any{"tid": 1, "groups": "agents"}) {
		t.Fatal("a non-string claim must not match")
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
	t.Run("entra keeps a caller's mapping", func(t *testing.T) {
		e := &ExternalIssuer{Issuer: "https://login.microsoftonline.com/" + tid + "/v2.0", ClaimMapping: map[string]string{"user_id": "sub"}}
		if err := ApplyIssuerPreset(e, IssuerPresetEntra); err != nil {
			t.Fatal(err)
		}
		if e.ClaimMapping["user_id"] != "sub" {
			t.Fatal("a preset never overrides a value the request set")
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
