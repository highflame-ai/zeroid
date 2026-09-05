package integration_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// End-to-end contract for the RFC 8707 `resource` request parameter
// (CAP-IDN-026, zeroid#258). These drive the real HTTP endpoint against a real
// database, so they cover the wiring the service-level unit tests cannot: JSON
// binding of the string-or-array shape, the Token() gate ordering, and what
// actually lands in the signed JWT.

const (
	mcpGithub = "https://gw.example.com/mcp/github"
	mcpSlack  = "https://gw.example.com/mcp/slack"
)

// resourceClaimOf normalizes the `resource` claim, which — like `aud` — may
// serialize as a bare string or an array. Returns nil when the claim is absent,
// which is the meaningful "not resource-bound" case.
func resourceClaimOf(t *testing.T, claims map[string]any) []string {
	t.Helper()
	switch v := claims["resource"].(type) {
	case nil:
		return nil
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			s, ok := e.(string)
			require.True(t, ok, "resource array element must be a string")
			out = append(out, s)
		}
		return out
	default:
		t.Fatalf("unexpected resource claim type %T", v)
		return nil
	}
}

// clientCredsBody registers an identity + confidential client and returns a
// ready client_credentials token request.
func clientCredsBody(t *testing.T, prefix string) map[string]any {
	t.Helper()
	agentID := uid(prefix)
	registerIdentity(t, agentID, []string{"data:read"})
	client := registerOAuthClient(t, agentID, []string{"data:read"})
	return map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"scope":         "data:read",
	}
}

func TestResourceIndicator_BindsClientCredentialsToken(t *testing.T) {
	t.Run("stamps aud and the resource claim", func(t *testing.T) {
		b := clientCredsBody(t, "res-cc-bind")
		b["resource"] = mcpGithub

		resp := post(t, "/oauth2/token", b, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		claims := decodeJWTPayload(t, decode(t, resp)["access_token"].(string))
		_ = resp.Body.Close()

		assert.Equal(t, []string{mcpGithub}, audienceOf(t, claims),
			"aud must be the requested resource, not the issuer default")
		assert.Equal(t, []string{mcpGithub}, resourceClaimOf(t, claims),
			"the resource claim is what INV-IDN-006 enforcement keys on")
	})

	t.Run("without the parameter nothing changes", func(t *testing.T) {
		// The baseline every existing caller depends on: aud stays the issuer
		// default and NO resource claim appears. Absence of the claim is what
		// tells Shield the token is unbound, so an accidental empty-but-present
		// claim would be a silent enforcement change.
		b := clientCredsBody(t, "res-cc-none")

		resp := post(t, "/oauth2/token", b, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		claims := decodeJWTPayload(t, decode(t, resp)["access_token"].(string))
		_ = resp.Body.Close()

		assert.Nil(t, resourceClaimOf(t, claims),
			"an unbound token must carry no resource claim at all")
		assert.NotEqual(t, []string{mcpGithub}, audienceOf(t, claims))
	})

	t.Run("array form binds every value", func(t *testing.T) {
		b := clientCredsBody(t, "res-cc-array")
		b["resource"] = []string{mcpGithub, mcpSlack}

		resp := post(t, "/oauth2/token", b, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		claims := decodeJWTPayload(t, decode(t, resp)["access_token"].(string))
		_ = resp.Body.Close()

		assert.ElementsMatch(t, []string{mcpGithub, mcpSlack}, audienceOf(t, claims))
		assert.ElementsMatch(t, []string{mcpGithub, mcpSlack}, resourceClaimOf(t, claims))
	})

	t.Run("string and single-element array agree", func(t *testing.T) {
		// The two encodings are the same request; a client should not get a
		// different token for choosing one.
		b1 := clientCredsBody(t, "res-cc-str")
		b1["resource"] = mcpGithub
		r1 := post(t, "/oauth2/token", b1, nil)
		require.Equal(t, http.StatusOK, r1.StatusCode)
		c1 := decodeJWTPayload(t, decode(t, r1)["access_token"].(string))
		_ = r1.Body.Close()

		b2 := clientCredsBody(t, "res-cc-arr1")
		b2["resource"] = []string{mcpGithub}
		r2 := post(t, "/oauth2/token", b2, nil)
		require.Equal(t, http.StatusOK, r2.StatusCode)
		c2 := decodeJWTPayload(t, decode(t, r2)["access_token"].(string))
		_ = r2.Body.Close()

		assert.Equal(t, audienceOf(t, c1), audienceOf(t, c2))
		assert.Equal(t, resourceClaimOf(t, c1), resourceClaimOf(t, c2))
	})
}

func TestResourceIndicator_Rejections(t *testing.T) {
	cases := []struct {
		name     string
		resource any
		wantErr  string
	}{
		{"fragment", mcpGithub + "#frag", "invalid_target"},
		{"relative reference", "/mcp/github", "invalid_target"},
		{"bare host", "gw.example.com/mcp", "invalid_target"},
		{"empty string", "", "invalid_target"},
		{"one bad value among good ones", []string{mcpGithub, "not-a-uri"}, "invalid_target"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := clientCredsBody(t, "res-reject")
			b["resource"] = tc.resource

			resp := post(t, "/oauth2/token", b, nil)
			require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			body := decode(t, resp)
			_ = resp.Body.Close()
			assert.Equal(t, tc.wantErr, body["error"])
		})
	}
}

// TestResourceIndicator_MutuallyExclusiveWithAudience pins the precedence rule.
// Two meanings on one claim with no discriminator is the shape of the bug that
// denied every MCP-targeted request in prod (shield#366); refusing the
// combination means there is no precedence to get wrong.
func TestResourceIndicator_MutuallyExclusiveWithAudience(t *testing.T) {
	body := map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": "external-principal-assertion",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"user_id":       uid("res-excl-user"),
		"audience":      "codeoid",
		"resource":      mcpGithub,
	}
	trusted := map[string]string{testTrustedServiceHeader: "trusted-service"}

	resp := post(t, "/oauth2/token", body, trusted)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	got := decode(t, resp)
	_ = resp.Body.Close()

	assert.Equal(t, "invalid_request", got["error"],
		"the conflict is a malformed request, not an unknown target")
	assert.Contains(t, got["error_description"], "mutually exclusive")
}

// TestResourceIndicator_CannotBeInjectedViaAdditionalClaims is the tripwire that
// keeps the claim's presence load-bearing. If a caller could set `resource`
// through the ungated additional_claims map, it could make an unbound token look
// bound — or widen a real binding — and Shield's enforcement would be reading a
// caller-controlled value.
func TestResourceIndicator_CannotBeInjectedViaAdditionalClaims(t *testing.T) {
	b := clientCredsBody(t, "res-inject")
	b["additional_claims"] = map[string]any{"resource": []string{mcpSlack}}

	resp := post(t, "/oauth2/token", b, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "reserved claims are dropped, not fatal")
	claims := decodeJWTPayload(t, decode(t, resp)["access_token"].(string))
	_ = resp.Body.Close()

	assert.Nil(t, resourceClaimOf(t, claims),
		"additional_claims must never be able to forge a resource binding")
}

func TestResourceIndicator_WideningAttemptViaAdditionalClaims(t *testing.T) {
	// Bound to github, additional_claims tries to add slack. The real binding
	// must survive untouched.
	b := clientCredsBody(t, "res-widen")
	b["resource"] = mcpGithub
	b["additional_claims"] = map[string]any{"resource": []string{mcpGithub, mcpSlack}}

	resp := post(t, "/oauth2/token", b, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	claims := decodeJWTPayload(t, decode(t, resp)["access_token"].(string))
	_ = resp.Body.Close()

	assert.Equal(t, []string{mcpGithub}, resourceClaimOf(t, claims),
		"a real binding must not be widenable through additional_claims")
	assert.Equal(t, []string{mcpGithub}, audienceOf(t, claims))
}

// TestResourceIndicator_RefreshGrantRefusesResource pins the permanent
// exclusion: a refresh continues an existing grant, so re-targeting a token
// already held would skip a fresh authorization decision.
func TestResourceIndicator_RefreshGrantRefusesResource(t *testing.T) {
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": "zid_rt_whatever",
		"resource":      mcpGithub,
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	got := decode(t, resp)
	_ = resp.Body.Close()

	assert.Equal(t, "invalid_target", got["error"],
		"rejected on the resource gate, before the refresh token is even looked up")
}

// TestResourceIndicator_AuthCodeSuppressesRefreshToken proves the refresh
// decision end-to-end. testMCPClientID is registered for the refresh_token
// grant and normally receives one (TestAuthorizationCodeMCPFlow asserts it), so
// the difference here is attributable to `resource` alone.
//
// This is the failure being prevented: the refresh path re-mints from state on
// the refresh-token row, and the RFC 8707 binding is not on it — it lives in
// CustomClaims, which rotation does not carry. A rotated token would come back
// unbound with no error anywhere, so "bind to X, refresh, use anywhere" would
// work silently and INV-IDN-006 enforcement would go quiet.
func TestResourceIndicator_AuthCodeSuppressesRefreshToken(t *testing.T) {
	authCodeExchange := func(t *testing.T, userID string, resource any) map[string]any {
		t.Helper()
		verifier, challenge := buildPKCEPair(t)
		code := buildAuthCode(t, testMCPClientID, userID, testRedirectURI, challenge, []string{"data:read"})
		body := map[string]any{
			"grant_type":    "authorization_code",
			"client_id":     testMCPClientID,
			"code":          code,
			"code_verifier": verifier,
			"redirect_uri":  testRedirectURI,
		}
		if resource != nil {
			body["resource"] = resource
		}
		resp := post(t, "/oauth2/token", body, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		out := decode(t, resp)
		_ = resp.Body.Close()
		return out
	}

	t.Run("baseline: the same client does get a refresh token", func(t *testing.T) {
		// Guards the test itself. Without this, a change that stopped issuing
		// refresh tokens entirely would make the assertion below pass for the
		// wrong reason.
		token := authCodeExchange(t, uid("res-ac-base"), nil)
		assert.NotEmpty(t, token["refresh_token"],
			"an unbound authorization_code exchange must still receive a refresh token")
	})

	t.Run("resource-bound exchange receives no refresh token", func(t *testing.T) {
		token := authCodeExchange(t, uid("res-ac-bound"), mcpGithub)

		assert.NotEmpty(t, token["access_token"], "the access token is still issued")
		assert.Empty(t, token["refresh_token"],
			"a resource-bound token must not come with a refresh token — the binding "+
				"is not carried across rotation, so refreshing would silently unbind it")

		claims := decodeJWTPayload(t, token["access_token"].(string))
		assert.Equal(t, []string{mcpGithub}, resourceClaimOf(t, claims),
			"the access token itself is still bound")
		assert.Equal(t, []string{mcpGithub}, audienceOf(t, claims))
	})
}

// Form-encoded requests reuse postForm from oauth_form_compat_test.go.

// TestResourceIndicator_FormEncoded covers the RFC 8707 §2 wire shape that
// RFC 6749 §3.1 would otherwise forbid: "the parameter can be included multiple
// times to indicate multiple resources". Before the repeatableFormFields
// carve-out this returned `duplicate OAuth parameter: resource`, which reads to
// an interop tester as "resource unsupported" rather than "we disagree about
// §3.1".
func TestResourceIndicator_FormEncoded(t *testing.T) {
	newForm := func(t *testing.T, prefix string) url.Values {
		t.Helper()
		b := clientCredsBody(t, prefix)
		return url.Values{
			"grant_type":    {b["grant_type"].(string)},
			"client_id":     {b["client_id"].(string)},
			"client_secret": {b["client_secret"].(string)},
			"account_id":    {b["account_id"].(string)},
			"project_id":    {b["project_id"].(string)},
			"scope":         {b["scope"].(string)},
		}
	}

	t.Run("single occurrence binds", func(t *testing.T) {
		f := newForm(t, "res-form-one")
		f.Set("resource", mcpGithub)

		resp := postForm(t, "/oauth2/token", f)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		claims := decodeJWTPayload(t, decode(t, resp)["access_token"].(string))
		_ = resp.Body.Close()

		assert.Equal(t, []string{mcpGithub}, resourceClaimOf(t, claims))
	})

	t.Run("repeated occurrences bind every value", func(t *testing.T) {
		f := newForm(t, "res-form-many")
		f["resource"] = []string{mcpGithub, mcpSlack}

		resp := postForm(t, "/oauth2/token", f)
		require.Equal(t, http.StatusOK, resp.StatusCode,
			"a conformant RFC 8707 multi-resource form request must be accepted")
		claims := decodeJWTPayload(t, decode(t, resp)["access_token"].(string))
		_ = resp.Body.Close()

		assert.ElementsMatch(t, []string{mcpGithub, mcpSlack}, resourceClaimOf(t, claims))
		assert.ElementsMatch(t, []string{mcpGithub, mcpSlack}, audienceOf(t, claims))
	})

	t.Run("other duplicated parameters are still rejected", func(t *testing.T) {
		// The carve-out must stay surgical: a repeated client_id is parameter
		// smuggling, not a spec feature.
		f := newForm(t, "res-form-dup")
		f["client_id"] = []string{f.Get("client_id"), "someone-else"}

		resp := postForm(t, "/oauth2/token", f)
		defer func() { _ = resp.Body.Close() }()
		assert.NotEqual(t, http.StatusOK, resp.StatusCode,
			"duplicate client_id must not be accepted")
	})

	t.Run("valueless resource is treated as omitted", func(t *testing.T) {
		// RFC 6749 §3.2. An empty value must not bind the token to "".
		f := newForm(t, "res-form-empty")
		f.Set("resource", "")

		resp := postForm(t, "/oauth2/token", f)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		claims := decodeJWTPayload(t, decode(t, resp)["access_token"].(string))
		_ = resp.Body.Close()

		assert.Nil(t, resourceClaimOf(t, claims),
			"an empty resource parameter must leave the token unbound, not bound to \"\"")
	})
}
