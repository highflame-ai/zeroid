package integration_test

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/mockidp"
)

// mapGroups adds claim_mapping.groups to an issuer row through the admin API,
// repeating the identity keys a claim_mapping patch must keep.
func mapGroups(t *testing.T, f *dbFederation, tn tiTenant, rowID, claim string) {
	t.Helper()
	status, row := f.call(t, http.MethodGet, "/external-issuers/"+rowID, nil, tn.headers)
	require.Equal(t, http.StatusOK, status, "%v", row)
	mapping := map[string]string{}
	for k, v := range row["claim_mapping"].(map[string]any) {
		mapping[k] = v.(string)
	}
	mapping["groups"] = claim
	status, body := f.call(t, http.MethodPatch, "/external-issuers/"+rowID, map[string]any{"claim_mapping": mapping}, tn.headers)
	require.Equal(t, http.StatusOK, status, "groups is editable after create: %v", body)
	assert.Equal(t, claim, body["claim_mapping"].(map[string]any)["groups"])

	status, row = f.call(t, http.MethodGet, "/external-issuers/"+rowID, nil, tn.headers)
	require.Equal(t, http.StatusOK, status, "%v", row)
	assert.Equal(t, claim, row["claim_mapping"].(map[string]any)["groups"], "the mapping is persisted")
}

// TestPersonGroups_IDTokenExchange: an issuer row that maps groups copies the
// ID token's groups into the issued token's RFC 9068 `groups` claim, and the
// claim travels with sub onto delegated tokens.
func TestPersonGroups_IDTokenExchange(t *testing.T) {
	p := newP1C(t)

	t.Run("an unmapped issuer copies no groups", func(t *testing.T) {
		resp := p.exchange(t, p.idToken(t, mockidp.ProfileEntraIDToken, map[string]any{"groups": []string{"eng"}}), nil)
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
		assert.NotContains(t, decodeIssuedTokenClaims(t, resp.AccessToken), "groups")
	})

	mapGroups(t, p.f, p.tn, p.rowID, "groups")

	resp := p.exchange(t, p.idToken(t, mockidp.ProfileEntraIDToken, map[string]any{"groups": []string{"eng", "oncall"}}), map[string]any{"scope": "tools:read"})
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
	root := decodeIssuedTokenClaims(t, resp.AccessToken)
	assert.Equal(t, []any{"eng", "oncall"}, root["groups"], "the IdP's groups, as an array of strings")
	assert.Equal(t, "user_hf_alice", root["sub"])
	assert.NotContains(t, root, "role", "groups never set role")
	assert.NotContains(t, root, "privilege_scope", "nor privilege_scope")

	t.Run("a single string is one group", func(t *testing.T) {
		resp := p.exchange(t, p.idToken(t, mockidp.ProfileEntraIDToken, map[string]any{"groups": "Domain Users"}), nil)
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
		assert.Equal(t, []any{"Domain Users"}, decodeIssuedTokenClaims(t, resp.AccessToken)["groups"])
	})
	t.Run("an absent claim is no groups claim, not an error", func(t *testing.T) {
		resp := p.exchange(t, p.idToken(t, mockidp.ProfileEntraIDToken, nil), nil)
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
		assert.NotContains(t, decodeIssuedTokenClaims(t, resp.AccessToken), "groups")
	})
	for name, v := range map[string]any{
		"a number":  42,
		"an object": map[string]any{"eng": true},
		"too many groups": func() []string {
			out := make([]string, 101)
			for i := range out {
				out[i] = fmt.Sprintf("g%d", i)
			}
			return out
		}(),
	} {
		t.Run(name+" does not fail the grant and copies nothing", func(t *testing.T) {
			resp := p.exchange(t, p.idToken(t, mockidp.ProfileEntraIDToken, map[string]any{"groups": v}), nil)
			require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
			assert.NotContains(t, decodeIssuedTokenClaims(t, resp.AccessToken), "groups")
		})
	}
	t.Run("an overage indicator is no groups", func(t *testing.T) {
		resp := p.exchange(t, p.idToken(t, mockidp.ProfileEntraIDToken, map[string]any{
			"_claim_names":   map[string]any{"groups": "src1"},
			"_claim_sources": map[string]any{"src1": map[string]any{"endpoint": "https://graph.example/getMemberObjects"}},
		}), nil)
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
		assert.NotContains(t, decodeIssuedTokenClaims(t, resp.AccessToken), "groups")
	})
	t.Run("additional_claims cannot set groups", func(t *testing.T) {
		resp := p.exchange(t, p.idToken(t, mockidp.ProfileEntraIDToken, map[string]any{"groups": []string{"eng"}}),
			map[string]any{"additional_claims": map[string]any{"groups": []string{"admins"}}})
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
		assert.Equal(t, []any{"eng"}, decodeIssuedTokenClaims(t, resp.AccessToken)["groups"])

		resp = p.exchange(t, p.idToken(t, mockidp.ProfileEntraIDToken, nil),
			map[string]any{"additional_claims": map[string]any{"groups": []string{"admins"}}})
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
		assert.NotContains(t, decodeIssuedTokenClaims(t, resp.AccessToken), "groups", "nor add it when the IdP sent none")
	})

	exchange := func(t *testing.T, subject string, key *ecdsa.PrivateKey, wimse string) map[string]any {
		t.Helper()
		ex := postFederation(t, p.f.http.URL, map[string]any{
			"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token": subject,
			"actor_token":   actorAssertion(t, key, wimse),
			"scope":         "tools:read",
		})
		require.Equal(t, http.StatusOK, ex.StatusCode, "body=%s", ex.RawBody)
		return decodeIssuedTokenClaims(t, ex.AccessToken)
	}
	t.Run("the same agent re-scoping keeps the groups", func(t *testing.T) {
		child := exchange(t, resp.AccessToken, p.agent.key, p.agent.wimse)
		assert.Equal(t, "user_hf_alice", child["sub"])
		assert.Equal(t, []any{"eng", "oncall"}, child["groups"])
	})
	t.Run("a delegated token keeps the person's groups, two hops down", func(t *testing.T) {
		sub := p.tn.agent(t)
		ex := postFederation(t, p.f.http.URL, map[string]any{
			"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token": resp.AccessToken,
			"actor_token":   actorAssertion(t, sub.key, sub.wimse),
			"scope":         "tools:read",
		})
		require.Equal(t, http.StatusOK, ex.StatusCode, "body=%s", ex.RawBody)
		child := decodeIssuedTokenClaims(t, ex.AccessToken)
		assert.EqualValues(t, 1, child["delegation_depth"])
		assert.Equal(t, "user_hf_alice", child["sub"])
		assert.Equal(t, []any{"eng", "oncall"}, child["groups"])

		third := p.tn.agent(t)
		grandchild := exchange(t, ex.AccessToken, third.key, third.wimse)
		assert.EqualValues(t, 2, grandchild["delegation_depth"])
		assert.Equal(t, []any{"eng", "oncall"}, grandchild["groups"])
	})
	t.Run("a person token without groups delegates without groups", func(t *testing.T) {
		bare := p.exchange(t, p.idToken(t, mockidp.ProfileEntraIDToken, nil), map[string]any{"scope": "tools:read"})
		require.Equal(t, http.StatusOK, bare.StatusCode, "body=%s", bare.RawBody)
		sub := p.tn.agent(t)
		assert.NotContains(t, exchange(t, bare.AccessToken, sub.key, sub.wimse), "groups")
	})
}

// TestPersonGroups_IDJAG: the ID-JAG grant copies the mapped groups too.
func TestPersonGroups_IDJAG(t *testing.T) {
	p := newP1B(t)
	mapGroups(t, p.f, p.tn, p.rowID, "member_of")

	resp := p.redeem(t, p.idJAG(t, map[string]any{"member_of": []string{"eng"}, "groups": []string{"ignored"}}), nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
	assert.Equal(t, []any{"eng"}, decodeIssuedTokenClaims(t, resp.AccessToken)["groups"], "the mapped claim, renamed by the admin")

	resp = p.redeem(t, p.idJAG(t, nil), nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
	assert.NotContains(t, decodeIssuedTokenClaims(t, resp.AccessToken), "groups", "no claim, no groups")

	resp = p.redeem(t, p.idJAG(t, map[string]any{"member_of": 7}), nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "a malformed claim does not fail the grant: %s", resp.RawBody)
	assert.NotContains(t, decodeIssuedTokenClaims(t, resp.AccessToken), "groups")
}

// TestPersonGroups_LegacyProfile: under the legacy profile an exchanged
// token's sub is the actor, so the person's groups stay on the person root.
func TestPersonGroups_LegacyProfile(t *testing.T) {
	p := newP1B(t)
	mapGroups(t, p.f, p.tn, p.rowID, "groups")
	resp := doRequest(t, http.MethodPut, adminPath("/tenant-settings"), map[string]any{"token_profile": "legacy"}, p.tn.headers)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	person := p.redeem(t, p.idJAG(t, map[string]any{"groups": []string{"eng"}}), nil)
	require.Equal(t, http.StatusOK, person.StatusCode, "body=%s", person.RawBody)
	assert.Equal(t, []any{"eng"}, decodeIssuedTokenClaims(t, person.AccessToken)["groups"], "a legacy person root's sub is the person")

	ex := postFederation(t, p.f.http.URL, map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": person.AccessToken,
		"actor_token":   actorAssertion(t, p.agent.key, p.agent.wimse),
		"scope":         "tools:read",
	})
	require.Equal(t, http.StatusOK, ex.StatusCode, "body=%s", ex.RawBody)
	child := decodeIssuedTokenClaims(t, ex.AccessToken)
	assert.Equal(t, p.agent.wimse, child["sub"])
	assert.NotContains(t, child, "groups", "the person's groups do not describe a legacy sub")
}

// TestPersonGroups_StaticIssuer: a static external_issuers entry maps groups
// the same way.
func TestPersonGroups_StaticIssuer(t *testing.T) {
	upstreamIss, aud := "https://static-groups.person.test", "https://zeroid-rp.static-groups.test"
	upstream := newFakeUpstreamIdP(t)
	defer upstream.Close()
	fedSrv, fedHTTP, fedCfg := newFederationServer(t, domain.ExternalIssuerConfig{
		Issuer: upstreamIss, JWKSURI: upstream.JWKSURL(), Audience: aud,
		ClaimMapping:    map[string]string{"user_id": "sub", "groups": "groups"},
		AllowedAccounts: []string{"acct-fed-001"},
	})
	defer fedHTTP.Close()
	defer func() { _ = fedSrv.Shutdown(context.Background()) }()

	exchange := func(t *testing.T, extra map[string]any) map[string]any {
		t.Helper()
		now := time.Now()
		claims := map[string]any{"iss": upstreamIss, "aud": aud, "sub": "alice", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()}
		for k, v := range extra {
			claims[k] = v
		}
		resp := postFederation(t, fedHTTP.URL, withClientAuth(t, map[string]any{
			"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token":      upstream.SignToken(t, claims),
			"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
			"account_id":         fedCfg.AccountID, "project_id": fedCfg.ProjectID,
		}, rpClient(t, aud)))
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
		return decodeIssuedTokenClaims(t, resp.AccessToken)
	}
	assert.Equal(t, []any{"eng", "ops"}, exchange(t, map[string]any{"groups": []string{"eng", "ops"}})["groups"])
	assert.NotContains(t, exchange(t, nil), "groups")
}

// TestPersonGroups_VerifyIDToken: the issuer's ID-token verification returns
// the groups it read, filtered and limited as the grants filter them.
func TestPersonGroups_VerifyIDToken(t *testing.T) {
	p := newProof(t)
	verify := func(t *testing.T, extra map[string]any) map[string]any {
		t.Helper()
		status, body := p.verify(t, p.tn, p.rowID, p.body(p.idToken(t, mockidp.ProfileEntraIDToken, extra)))
		require.Equal(t, http.StatusOK, status, "%v", body)
		return body
	}
	assert.NotContains(t, verify(t, map[string]any{"groups": []string{"eng"}}), "groups", "unmapped: no groups")

	mapGroups(t, p.f, p.tn, p.rowID, "groups")
	assert.Equal(t, []any{"eng", "ops"}, verify(t, map[string]any{"groups": []any{"eng", 3, "ops", "eng"}})["groups"],
		"non-strings skipped, duplicates collapsed")
	assert.NotContains(t, verify(t, nil), "groups", "no claim: no groups")
	assert.NotContains(t, verify(t, map[string]any{"groups": 42}), "groups", "malformed: no groups, still verified")
}

// TestPersonGroups_EmptyMappingTurnsGroupsOff: "groups": "" means read no
// groups. It is stored as no mapping, so GET shows no groups key.
func TestPersonGroups_EmptyMappingTurnsGroupsOff(t *testing.T) {
	f := newDBFederation(t)
	tn := newTITenant(t)
	status, row := f.call(t, http.MethodPost, "/external-issuers", map[string]any{
		"kind":          "person",
		"issuer":        f.idp.OktaIssuer(),
		"claim_mapping": map[string]string{"user_id": "sub", "email": "email", "email_verified": "email_verified", "groups": ""},
	}, tn.headers)
	require.Equal(t, http.StatusCreated, status, "an empty groups mapping is accepted on create: %v", row)
	assert.NotContains(t, row["claim_mapping"], "groups")
	rowID := row["id"].(string)

	mapGroups(t, f, tn, rowID, "groups")

	status, body := f.call(t, http.MethodPatch, "/external-issuers/"+rowID, map[string]any{"claim_mapping": map[string]string{
		"user_id": "sub", "email": "email", "email_verified": "email_verified", "groups": "",
	}}, tn.headers)
	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.NotContains(t, body["claim_mapping"], "groups", "an empty groups patch removes the mapping")
	status, body = f.call(t, http.MethodGet, "/external-issuers/"+rowID, nil, tn.headers)
	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.NotContains(t, body["claim_mapping"], "groups")

	mapGroups(t, f, tn, rowID, "groups")
	status, body = f.call(t, http.MethodPatch, "/external-issuers/"+rowID, map[string]any{"claim_mapping": map[string]string{
		"user_id": "sub", "email": "email", "email_verified": "email_verified",
	}}, tn.headers)
	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.NotContains(t, body["claim_mapping"], "groups", "a patch without groups removes it; nothing refills it")
}
