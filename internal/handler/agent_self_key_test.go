package handler

import (
	"testing"

	internalMiddleware "github.com/highflame-ai/zeroid/internal/middleware"
)

// Only the agent's own token may set its first key: that enrollment is
// trust-on-first-use, authorized by the token alone.
func TestSelfKeyTokenRefusal(t *testing.T) {
	const iss = "https://zeroid.example.com"
	own := func(c internalMiddleware.AgentClaims) internalMiddleware.AgentClaims {
		c.Issuer, c.Audience = iss, []string{iss}
		return c
	}
	cases := []struct {
		name   string
		claims internalMiddleware.AgentClaims
		allow  bool
	}{
		{"api key", own(internalMiddleware.AgentClaims{GrantType: "api_key", PrincipalType: "workload"}), true},
		{"client credentials", own(internalMiddleware.AgentClaims{GrantType: "client_credentials"}), true},
		{"jwt-bearer, legacy profile", own(internalMiddleware.AgentClaims{GrantType: "jwt_bearer"}), true},
		{"token exchange", own(internalMiddleware.AgentClaims{GrantType: "token_exchange", PrincipalType: "workload"}), false},
		{"CIBA", own(internalMiddleware.AgentClaims{GrantType: "urn:openid:params:grant-type:ciba"}), false},
		{"proof token (no grant_type)", own(internalMiddleware.AgentClaims{}), false},
		{"authorization code", own(internalMiddleware.AgentClaims{GrantType: "authorization_code"}), false},
		{"refresh token", own(internalMiddleware.AgentClaims{GrantType: "refresh_token"}), false},
		{"ID-JAG under rfc8693", own(internalMiddleware.AgentClaims{GrantType: "jwt_bearer", PrincipalType: "user"}), false},
		{"api key bound to a resource", internalMiddleware.AgentClaims{GrantType: "api_key", Issuer: iss, Audience: []string{"https://mcp.example.com"}}, false},
		{"client credentials bound to a gateway", internalMiddleware.AgentClaims{GrantType: "client_credentials", Issuer: iss, Audience: []string{"https://gateway.example.com"}}, false},
		{"ID-JAG under legacy", own(internalMiddleware.AgentClaims{GrantType: "jwt_bearer", UserIDIssuer: "https://idp.example.com"}), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason := selfKeyTokenRefusal(tc.claims)
			if tc.allow && reason != "" {
				t.Fatalf("refused: %s", reason)
			}
			if !tc.allow && reason == "" {
				t.Fatal("allowed, want refused")
			}
		})
	}
}
