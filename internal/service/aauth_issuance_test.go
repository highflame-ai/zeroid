package service

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/highflame-ai/zeroid/domain"
)

// TestAAuthGrantTypesStayAtTheirEndpoints pins the issuance chokepoint: the
// AAuth grant types are minted only by their own endpoints, so an admin issue
// or a rotation can never produce an OAuth token labelled as an agent token,
// or an agent token under another grant type.
func TestAAuthGrantTypesStayAtTheirEndpoints(t *testing.T) {
	svc := NewCredentialService(nil, nil, nil, nil, "https://issuer.example.test", 900, 3600, 30)
	identity := &domain.Identity{IdentityType: domain.IdentityTypeAgent, Status: domain.IdentityStatusActive}
	signer := func(string, time.Time, time.Time) (string, error) { return "agent-token", nil }

	cases := []struct {
		name string
		req  IssueRequest
	}{
		{"agent grant without the agent token signer", IssueRequest{Identity: identity, GrantType: domain.GrantTypeAAuthAgent}},
		{"agent token signer under another grant", IssueRequest{Identity: identity, GrantType: domain.GrantTypeClientCredentials, AgentTokenSigner: signer}},
		{"agent token signer under the default grant", IssueRequest{Identity: identity, AgentTokenSigner: signer}},
		{"bridge grant without its parent agent token", IssueRequest{Identity: identity, GrantType: domain.GrantTypeAAuthBridge}},
		{"bridge grant by its URN, without its parent", IssueRequest{Identity: identity, GrantType: domain.GrantType(domain.GrantTypeAAuthBridgeURN)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := svc.IssueCredential(context.Background(), tc.req)
			if !errors.Is(err, ErrGrantTypeNotIssuable) {
				t.Fatalf("expected ErrGrantTypeNotIssuable, got %v", err)
			}
		})
	}
}

func TestAAuthGrantTypesAreOptIn(t *testing.T) {
	for _, g := range []domain.GrantType{domain.GrantTypeAAuthAgent, domain.GrantTypeAAuthBridge} {
		if !domain.IsValidGrantType(string(g)) {
			t.Errorf("%s must be a valid grant type, so a credential policy can list it", g)
		}
		if slices.Contains(domain.DefaultAllowedGrantTypes(), string(g)) {
			t.Errorf("%s must not be in the default policy: a tenant opts in by listing it", g)
		}
		if !g.IsAAuth() {
			t.Errorf("%s must report IsAAuth", g)
		}
	}
	if got := domain.NormalizeGrantType(domain.GrantTypeAAuthBridgeURN); got != domain.GrantTypeAAuthBridge {
		t.Errorf("the bridge URN normalizes to %q, want %q", got, domain.GrantTypeAAuthBridge)
	}
	if !domain.GrantType(domain.GrantTypeAAuthBridgeURN).IsAAuth() {
		t.Error("the bridge URN must report IsAAuth, so a row stored under it cannot be rotated")
	}
	if domain.GrantTypeClientCredentials.IsAAuth() {
		t.Error("client_credentials is not an AAuth grant type")
	}
}
