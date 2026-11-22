package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/oautherror"
)

func allowAll(context.Context, ReservedScopeGrant) error { return nil }

func TestReservedScopes_SetNeedsAuthorizer(t *testing.T) {
	r := &ReservedScopes{}
	if err := r.Set([]string{"hf."}, nil, time.Minute); err == nil {
		t.Fatal("prefixes without an authorizer must be refused")
	}
	if err := r.Set(nil, nil, 0); err != nil {
		t.Fatalf("no prefixes turns it off: %v", err)
	}
}

func TestReservedScopes_In(t *testing.T) {
	r := &ReservedScopes{}
	if err := r.Set([]string{"hf."}, allowAll, 0); err != nil {
		t.Fatal(err)
	}
	got := r.in([]string{"hf.config.manage", "data:read", "hfx"})
	if len(got) != 1 || got[0] != "hf.config.manage" {
		t.Fatalf("in = %v", got)
	}
	if (*ReservedScopes)(nil).in([]string{"hf.config.manage"}) != nil {
		t.Fatal("nil ReservedScopes reserves nothing")
	}
}

// CreateKey refuses a reserved scope outside the trusted write, before any
// lookup or insert.
func TestCreateKeyRefusesUntrustedReservedScope(t *testing.T) {
	r := &ReservedScopes{}
	if err := r.Set([]string{"hf."}, allowAll, 0); err != nil {
		t.Fatal(err)
	}
	svc := &APIKeyService{reserved: r}
	_, err := svc.CreateKey(context.Background(), CreateAPIKeyRequest{Scopes: []string{"hf.config.manage"}})
	if !errors.Is(err, ErrReservedScopeWriteNotTrusted) {
		t.Fatalf("want ErrReservedScopeWriteNotTrusted, got %v", err)
	}
	_, err = svc.CreateKey(WithReservedScopeWrite(context.Background()), CreateAPIKeyRequest{Scopes: []string{"hf.config.manage"}})
	if errors.Is(err, ErrReservedScopeWriteNotTrusted) {
		t.Fatal("the trusted write must pass the reserved-scope check")
	}
}

// IssueCredential is the chokepoint: no path but the api_key grant's checks
// issues a reserved scope.
func TestIssueCredentialRefusesUnauthorizedReservedScope(t *testing.T) {
	r := &ReservedScopes{}
	if err := r.Set([]string{"hf."}, allowAll, 0); err != nil {
		t.Fatal(err)
	}
	s := &CredentialService{reserved: r, defaultTTL: 300, maxTTL: 3600}
	_, _, err := s.IssueCredential(context.Background(), IssueRequest{
		Identity: &domain.Identity{ID: "id-1", Status: domain.IdentityStatusActive, IdentityType: domain.IdentityTypeService},
		Scopes:   []string{"hf.config.manage"},
	})
	if !errors.Is(err, ErrScopesNotAllowed) || !strings.Contains(err.Error(), "only on the api_key grant") {
		t.Fatalf("want the reserved-scope refusal, got %v", err)
	}
}

// A sub-second or negative cap would round to 0, which means no cap, so Set
// refuses it and keeps the previous configuration.
func TestReservedScopes_SetRefusesSubSecondMaxTTL(t *testing.T) {
	r := &ReservedScopes{}
	if err := r.Set([]string{"hf."}, allowAll, time.Minute); err != nil {
		t.Fatal(err)
	}
	for _, d := range []time.Duration{-time.Second, time.Nanosecond, 500 * time.Millisecond} {
		if err := r.Set([]string{"hf."}, allowAll, d); err == nil {
			t.Errorf("maxTTL %s must be refused", d)
		}
	}
	if _, maxTTL := r.authorizer(); maxTTL != 60 {
		t.Fatalf("a refused Set changed maxTTL to %d", maxTTL)
	}
	for d, want := range map[time.Duration]int{0: 0, time.Second: 1} {
		if err := r.Set([]string{"hf."}, allowAll, d); err != nil {
			t.Fatalf("maxTTL %s: %v", d, err)
		}
		if _, got := r.authorizer(); got != want {
			t.Fatalf("maxTTL %s stored as %d, want %d", d, got, want)
		}
	}
}

// The reserved lifetime caps the token after every other clamp, never
// lengthens a shorter one, and 0 leaves the lifetime alone. issueTTL is the
// lifetime IssueCredential signs; a full IssueCredential needs the database.
func TestIssueTTL_ReservedMaxTTL(t *testing.T) {
	s := &CredentialService{defaultTTL: 300, maxTTL: 3600}
	id := &domain.Identity{ID: "id-1", Status: domain.IdentityStatusActive}
	cases := []struct {
		name           string
		ttl, max, want int
	}{
		{"caps the default", 0, 120, 120},
		{"caps a requested lifetime", 3000, 120, 120},
		{"never lengthens a shorter one", 60, 120, 60},
		{"0 is no cap", 0, 0, 300},
	}
	for _, tc := range cases {
		got, _, err := s.issueTTL(IssueRequest{Identity: id, TTL: tc.ttl, MaxTTL: tc.max})
		if err != nil || got != tc.want {
			t.Errorf("%s: issueTTL = %d, %v; want %d", tc.name, got, err, tc.want)
		}
	}
}

// reservedOAuth builds an OAuthService whose reserved prefix is "hf." with a
// 2-minute cap and the given authorizer, counting its calls.
func reservedOAuth(t *testing.T, authorize ReservedScopeAuthorizer) (*OAuthService, *[]ReservedScopeGrant) {
	t.Helper()
	var calls []ReservedScopeGrant
	r := &ReservedScopes{}
	if err := r.Set([]string{"hf."}, func(ctx context.Context, g ReservedScopeGrant) error {
		calls = append(calls, g)
		return authorize(ctx, g)
	}, 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	return &OAuthService{credentialSvc: &CredentialService{reserved: r}}, &calls
}

func TestAuthorizeReservedScopes(t *testing.T) {
	const scope = "hf.config.manage"
	service := &domain.Identity{ID: "id-1", IdentityType: domain.IdentityTypeService}
	key := func(createdBy string, scopes ...string) *domain.APIKey {
		return &domain.APIKey{ID: "key-1", AccountID: "acct", ProjectID: "proj", CreatedBy: createdBy, Scopes: scopes}
	}
	refused := func(t *testing.T, err error, code string, issue IssueRequest) *OAuthError {
		t.Helper()
		var oe *OAuthError
		if !errors.As(err, &oe) || oe.Code != code {
			t.Fatalf("want %s, got %v", code, err)
		}
		if issue.ReservedScopesAuthorized || issue.MaxTTL != 0 {
			t.Fatalf("a refused grant was marked authorized: %+v", issue)
		}
		return oe
	}

	t.Run("no reserved scope never calls the authorizer", func(t *testing.T) {
		s, calls := reservedOAuth(t, allowAll)
		issue := IssueRequest{Scopes: []string{"data:read"}}
		if err := s.authorizeReservedScopes(context.Background(), &issue, key("alice"), service); err != nil {
			t.Fatal(err)
		}
		if len(*calls) != 0 || issue.ReservedScopesAuthorized {
			t.Fatalf("calls=%d authorized=%v", len(*calls), issue.ReservedScopesAuthorized)
		}
	})

	t.Run("key row does not list the scope", func(t *testing.T) {
		s, calls := reservedOAuth(t, allowAll)
		issue := IssueRequest{Scopes: []string{scope}}
		err := s.authorizeReservedScopes(context.Background(), &issue, key("alice", "data:read"), service)
		refused(t, err, oautherror.InvalidScope, issue)
		if len(*calls) != 0 {
			t.Fatal("authorizer called for an unlisted scope")
		}
	})

	for _, tc := range []struct {
		name     string
		identity *domain.Identity
		creator  string
	}{
		{"agent identity", &domain.Identity{ID: "id-1", IdentityType: domain.IdentityTypeAgent}, "alice"},
		{"no identity", nil, "alice"},
		{"empty creator", service, ""},
		{"system creator", service, "system:rotation"},
		{"padded creator", service, " alice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, calls := reservedOAuth(t, allowAll)
			issue := IssueRequest{Scopes: []string{scope}}
			err := s.authorizeReservedScopes(context.Background(), &issue, key(tc.creator, scope), tc.identity)
			refused(t, err, oautherror.InvalidScope, issue)
			if len(*calls) != 0 {
				t.Fatal("authorizer called without a usable service creator")
			}
		})
	}

	t.Run("authorizer refuses", func(t *testing.T) {
		s, _ := reservedOAuth(t, func(context.Context, ReservedScopeGrant) error {
			return fmt.Errorf("%w: alice is no longer an admin", ErrReservedScopeDenied)
		})
		issue := IssueRequest{Scopes: []string{scope}}
		err := s.authorizeReservedScopes(context.Background(), &issue, key("alice", scope), service)
		oe := refused(t, err, oautherror.InvalidGrant, issue)
		if !strings.Contains(oe.Description, "alice is no longer an admin") {
			t.Fatalf("description %q lacks the refusal", oe.Description)
		}
	})

	t.Run("authorizer fails", func(t *testing.T) {
		cause := errors.New("dial http://internal-admin:8040")
		s, _ := reservedOAuth(t, func(context.Context, ReservedScopeGrant) error { return cause })
		issue := IssueRequest{Scopes: []string{scope}}
		err := s.authorizeReservedScopes(context.Background(), &issue, key("alice", scope), service)
		oe := refused(t, err, oautherror.ServerError, issue)
		if strings.Contains(oe.Description, "internal-admin") || strings.Contains(err.Error(), "internal-admin") {
			t.Fatalf("the cause reached the client: %q", oe.Description)
		}
		if !errors.Is(err, cause) {
			t.Fatal("the cause should stay wrapped for logs")
		}
	})

	t.Run("allowed", func(t *testing.T) {
		s, calls := reservedOAuth(t, allowAll)
		issue := IssueRequest{Scopes: []string{"data:read", scope}}
		if err := s.authorizeReservedScopes(context.Background(), &issue, key("alice", scope), service); err != nil {
			t.Fatal(err)
		}
		if !issue.ReservedScopesAuthorized || issue.MaxTTL != 120 {
			t.Fatalf("authorized=%v MaxTTL=%d", issue.ReservedScopesAuthorized, issue.MaxTTL)
		}
		want := ReservedScopeGrant{AccountID: "acct", ProjectID: "proj", APIKeyID: "key-1", CreatedBy: "alice", Scopes: []string{scope}}
		if len(*calls) != 1 || !grantEqual((*calls)[0], want) {
			t.Fatalf("authorizer saw %+v, want %+v", *calls, want)
		}
	})
}

func grantEqual(a, b ReservedScopeGrant) bool {
	return a.AccountID == b.AccountID && a.ProjectID == b.ProjectID && a.APIKeyID == b.APIKeyID &&
		a.CreatedBy == b.CreatedBy && slices.Equal(a.Scopes, b.Scopes)
}

// A scope with whitespace inside it is read as several scopes wherever the
// space-delimited `scope` claim is split, so a reserved part must count.
func TestReservedScopes_InSeesWhitespaceSeparatedParts(t *testing.T) {
	r := &ReservedScopes{}
	if err := r.Set([]string{"hf."}, allowAll, 0); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"data:read hf.config.manage", " hf.config.manage", "x\thf.config.manage", "x\nhf.config.manage"} {
		if got := r.in([]string{s}); len(got) != 1 {
			t.Errorf("in(%q) = %v, want it reserved", s, got)
		}
	}
	if got := r.in([]string{"data:read other"}); got != nil {
		t.Errorf("in = %v, want nil", got)
	}
}

// CreateKey refuses a scope containing whitespace before any other check, so
// neither the reserved-scope nor the approval-channel gate can be split around.
func TestCreateKeyRefusesWhitespaceInScope(t *testing.T) {
	svc := &APIKeyService{reserved: &ReservedScopes{}}
	for _, s := range []string{"a b", " a", "a\t", "a\nb"} {
		_, err := svc.CreateKey(WithReservedScopeWrite(context.Background()), CreateAPIKeyRequest{Scopes: []string{s}})
		if !errors.Is(err, ErrScopeHasWhitespace) {
			t.Errorf("scope %q: want ErrScopeHasWhitespace, got %v", s, err)
		}
	}
}
