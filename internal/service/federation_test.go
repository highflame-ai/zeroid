package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The gate + validation arms of FederatedCredentialExchange all return BEFORE
// IssueCredential, so they are exercisable on a minimal OAuthService with no DB
// or signing. The success mint (sub/act/aud) is covered end-to-end in authn's
// integration test, which drives the real endpoint against a real store.

func TestFederatedCredentialExchange_TrustedServiceGate(t *testing.T) {
	req := FederatedExchangeRequest{
		AccountID:    "acct-1",
		ProjectID:    "proj-1",
		SubjectWIMSE: "spiffe://highflame.io/ns/proj-1/agent-x",
		Audience:     "https://api.anthropic.com",
	}

	t.Run("no validator configured is refused", func(t *testing.T) {
		svc := &OAuthService{} // trustedServiceValidator == nil
		_, err := svc.FederatedCredentialExchange(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not configured")
	})

	t.Run("untrusted caller is refused", func(t *testing.T) {
		svc := &OAuthService{trustedServiceValidator: func(context.Context) (string, error) {
			return "", errors.New("no trusted-service header")
		}}
		_, err := svc.FederatedCredentialExchange(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a trusted service")
	})
}

func TestFederatedCredentialExchange_ValidatesShape(t *testing.T) {
	// Passes the gate, so validation failures surface (all before IssueCredential).
	trusted := &OAuthService{trustedServiceValidator: func(context.Context) (string, error) {
		return "firehog", nil
	}}
	base := FederatedExchangeRequest{
		AccountID:    "acct-1",
		ProjectID:    "proj-1",
		SubjectWIMSE: "spiffe://highflame.io/ns/proj-1/agent-x",
		Audience:     "https://api.anthropic.com",
	}

	cases := []struct {
		name   string
		mutate func(r *FederatedExchangeRequest)
		errSub string
	}{
		{"missing account", func(r *FederatedExchangeRequest) { r.AccountID = "" }, "account_id and project_id"},
		{"missing project", func(r *FederatedExchangeRequest) { r.ProjectID = "" }, "account_id and project_id"},
		{"missing subject wimse", func(r *FederatedExchangeRequest) { r.SubjectWIMSE = "" }, "subject_wimse is required"},
		{"http audience", func(r *FederatedExchangeRequest) { r.Audience = "http://api.anthropic.com" }, "invalid federation audience"},
		{"loopback audience", func(r *FederatedExchangeRequest) { r.Audience = "http://127.0.0.1/t" }, "invalid federation audience"},
		{"opaque audience", func(r *FederatedExchangeRequest) { r.Audience = "anthropic" }, "invalid federation audience"},
		{"userinfo audience", func(r *FederatedExchangeRequest) {
			r.Audience = "https://api.anthropic.com:x@evil.example"
		}, "invalid federation audience"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			tc.mutate(&r)
			_, err := trusted.FederatedCredentialExchange(context.Background(), r)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.errSub)
		})
	}
}

func TestValidateFederationAudience(t *testing.T) {
	ok := []string{
		"https://api.anthropic.com",
		"https://api.anthropic.com/v1/oauth/token",
		"https://sts.googleapis.com",
	}
	for _, a := range ok {
		require.NoError(t, validateFederationAudience(a), a)
	}

	bad := map[string]string{
		"empty":            "",
		"http":             "http://api.anthropic.com",
		"http loopback":    "http://127.0.0.1:8040/t",
		"no scheme":        "api.anthropic.com",
		"opaque":           "anthropic",
		"no host":          "https:///path",
		"userinfo spoof":   "https://api.anthropic.com:x@evil.example/h",
		"userinfo present": "https://user@api.anthropic.com/t",
		"ftp":              "ftp://api.anthropic.com",
	}
	for name, a := range bad {
		t.Run(name, func(t *testing.T) {
			require.Error(t, validateFederationAudience(a), a)
		})
	}
}
