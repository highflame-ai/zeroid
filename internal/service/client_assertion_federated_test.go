package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/oautherror"
)

// Any account can add its own issuer and bind any subject string, so the
// client_id is always issuer-qualified: the same sub under two issuers (two
// clusters, or a lookalike issuer in another tenant) never shares one.
func TestFederatedClientID(t *testing.T) {
	for _, sub := range []string{"system:serviceaccount:agents:foo", "arn:aws:iam::111122223333:role/agent", "spiffe://example.org/agent"} {
		a, b := federatedClientID("https://issuer-a.example", sub), federatedClientID("https://issuer-b.example", sub)
		if a != "https://issuer-a.example#"+sub {
			t.Fatalf("got %q, want <iss>#<sub>", a)
		}
		if a == b {
			t.Fatalf("%q under two issuers shares a client_id", sub)
		}
	}
}

// '#' is reserved for federated client ids, so a registered client named
// <iss>#<sub> cannot share a client_id with the agent that sub is bound to.
func TestRegisterClientRefusesHashInClientID(t *testing.T) {
	svc := NewOAuthClientService(nil)
	for _, id := range []string{"https://issuer.example#system:serviceaccount:agents:foo", "app#1", "#"} {
		_, _, err := svc.RegisterClient(context.Background(), RegisterClientRequest{ClientID: id, Name: "client"})
		if !errors.Is(err, ErrInvalidClientMetadata) {
			t.Fatalf("client_id %q: want ErrInvalidClientMetadata, got %v", id, err)
		}
	}
}

// signedWorkloadAssertion is an ES256 token from iss for sub, signed by a key
// no issuer trusts: these tests stop before the signature is checked.
func signedWorkloadAssertion(t *testing.T, iss string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	tok, err := jwt.NewBuilder().Issuer(iss).Subject("system:serviceaccount:agents:foo").
		Audience([]string{"https://zeroid.example"}).IssuedAt(now).Expiration(now.Add(time.Minute)).
		JwtID("jti-1").Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), key))
	require.NoError(t, err)
	return string(signed)
}

// A server-side failure to verify keeps its 5xx status but not its
// description, which names the issuer: an unsigned probe must not learn that
// its iss matched a trusted row.
func TestFederatedClientCredentials_ServerFailureNamesNoIssuer(t *testing.T) {
	const iss = "https://cluster.internal.example"
	reg := NewDBExternalIssuerRegistry(&fakeIssuerRows{}, true, nil)
	defer reg.Close()
	entry, err := reg.EntryForRow(issuerRow("w1", "acct", iss, domain.IssuerKindWorkload, refusedURL))
	require.NoError(t, err)

	_, err = (&OAuthService{}).federatedClientCredentials(context.Background(), TokenRequest{
		ClientAssertion:     signedWorkloadAssertion(t, iss),
		ClientAssertionType: clientAssertionTypeJWTBearer,
	}, entry)
	var oe *OAuthError
	require.ErrorAs(t, err, &oe)
	require.GreaterOrEqual(t, oe.HTTPStatus, http.StatusInternalServerError)
	require.Equal(t, federatedAuthUnavailable, oe.Description)
	require.NotContains(t, oe.Error(), "cluster.internal.example")
}

// Before the assertion is verified, an iss whose workload rows match it
// ambiguously, or not at all, gets the generic refusal an unknown client
// gets. Two rows matching one token cannot be stored through the admin API
// (one row per kind for a customer-unique issuer, disjoint pins for a shared
// one), so the ambiguous case is exercised here.
func TestWorkloadIssuerFor_UnusableRowsAreRefusedGenerically(t *testing.T) {
	const iss = "https://cluster.example"
	constrained := issuerRow("w1", "acct", iss, domain.IssuerKindWorkload, refusedURL)
	constrained.ClaimConstraints = map[string][]string{"team": {"payments"}}
	cases := map[string][]*domain.ExternalIssuer{
		"constraints unmet": {constrained},
		"ambiguous": {
			issuerRow("w1", "acct", iss, domain.IssuerKindWorkload, refusedURL),
			issuerRow("w2", "acct", iss, domain.IssuerKindWorkload, refusedURL),
		},
	}
	for name, rows := range cases {
		t.Run(name, func(t *testing.T) {
			reg := NewDBExternalIssuerRegistry(&fakeIssuerRows{rows: rows}, true, nil)
			defer reg.Close()
			s := &OAuthService{externalIssuerRegistry: reg}
			_, ok, err := s.workloadIssuerFor(context.Background(), TokenRequest{ClientAssertion: signedWorkloadAssertion(t, iss)})
			require.False(t, ok)
			var oe *OAuthError
			require.ErrorAs(t, err, &oe)
			require.Equal(t, oautherror.InvalidClient, oe.Code)
			require.Equal(t, "invalid client credentials", oe.Description)
			require.False(t, strings.Contains(oe.Error(), "ambiguous") || strings.Contains(oe.Error(), "constraint"))
		})
	}
}
