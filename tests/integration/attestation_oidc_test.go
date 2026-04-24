package integration_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// oidcIssuer stands up a minimal OIDC discovery + JWKS server for tests so
// the attestation OIDC verifier has a real issuer to talk to. It returns
// the issuer URL and a function that mints signed JWTs with caller-supplied
// claims.
type oidcIssuer struct {
	URL     string
	signKey jwk.Key
	sign    func(claims map[string]any) string
	close   func()
}

func newOIDCIssuer(t *testing.T) *oidcIssuer {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signKey, err := jwk.FromRaw(priv)
	require.NoError(t, err)
	require.NoError(t, signKey.Set(jwk.KeyIDKey, "test-issuer-key-1"))
	require.NoError(t, signKey.Set(jwk.AlgorithmKey, jwa.RS256))

	pubKey, err := signKey.PublicKey()
	require.NoError(t, err)
	require.NoError(t, pubKey.Set(jwk.KeyIDKey, "test-issuer-key-1"))
	require.NoError(t, pubKey.Set(jwk.AlgorithmKey, jwa.RS256))
	require.NoError(t, pubKey.Set(jwk.KeyUsageKey, "sig"))

	jwks := jwk.NewSet()
	require.NoError(t, jwks.AddKey(pubKey))

	mux := http.NewServeMux()
	var issuerURL string

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   issuerURL,
			"jwks_uri": issuerURL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})

	srv := httptest.NewServer(mux)
	issuerURL = srv.URL

	sign := func(claims map[string]any) string {
		t.Helper()
		tok := jwt.New()
		require.NoError(t, tok.Set(jwt.IssuerKey, issuerURL))
		require.NoError(t, tok.Set(jwt.IssuedAtKey, time.Now().Unix()))
		require.NoError(t, tok.Set(jwt.ExpirationKey, time.Now().Add(5*time.Minute).Unix()))
		for k, v := range claims {
			require.NoError(t, tok.Set(k, v))
		}
		signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, signKey))
		require.NoError(t, err)
		return string(signed)
	}

	return &oidcIssuer{URL: issuerURL, signKey: signKey, sign: sign, close: srv.Close}
}

// submitAttestation wraps the submit endpoint so each test can post a proof
// in one line. Returns the created record's UUID.
func submitAttestation(t *testing.T, identityID, proofType, proofValue string) string {
	t.Helper()
	resp := post(t, adminPath("/attestation/submit"), map[string]any{
		"identity_id": identityID,
		"level":       "software",
		"proof_type":  proofType,
		"proof_value": proofValue,
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, resp.StatusCode,
		"attestation submit expected 201")
	return decode(t, resp)["id"].(string)
}

func verifyAttestation(t *testing.T, attestationID string) *http.Response {
	t.Helper()
	return post(t, adminPath("/attestation/verify"), map[string]any{
		"attestation_id": attestationID,
	}, adminHeaders())
}

func upsertOIDCPolicy(t *testing.T, cfg map[string]any) {
	t.Helper()
	body := map[string]any{
		"proof_type": "oidc_token",
		"config":     cfg,
	}
	resp := doRequest(t, http.MethodPut, adminPath("/attestation-policies"), body, adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode, "upsert policy expected 200")
	_ = resp.Body.Close()
}

// TestAttestationFailsClosedWithNoPolicy verifies the top-level contract:
// a submitted oidc_token attestation must not be marked verified when no
// AttestationPolicy exists for the tenant + proof type. This is the fix
// for the "any submitted attestation becomes verified trust" bug.
func TestAttestationFailsClosedWithNoPolicy(t *testing.T) {
	reg := registerAgent(t, uid("attest-no-policy"))
	token := newOIDCIssuer(t).sign(map[string]any{"sub": "ci-job-1"})
	id := submitAttestation(t, reg.AgentID, "oidc_token", token)

	resp := verifyAttestation(t, id)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"verify must fail closed when the tenant has no attestation policy")
}

// TestAttestationOIDCVerifierHappyPath covers the full working flow:
// trusted issuer + signed JWT + matching audience/claims → verified,
// identity trust promoted, credential issued.
func TestAttestationOIDCVerifierHappyPath(t *testing.T) {
	iss := newOIDCIssuer(t)
	defer iss.close()

	reg := registerAgent(t, uid("attest-oidc-ok"))

	upsertOIDCPolicy(t, map[string]any{
		"issuers": []map[string]any{{
			"url":       iss.URL,
			"audiences": []string{"zeroid://test"},
			"required_claims": map[string]string{
				"repository": "myorg/myrepo",
			},
		}},
	})

	token := iss.sign(map[string]any{
		"sub":        "ci-job-42",
		"aud":        "zeroid://test",
		"repository": "myorg/myrepo",
	})
	id := submitAttestation(t, reg.AgentID, "oidc_token", token)

	resp := verifyAttestation(t, id)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, "happy-path verify expected 200")

	body := decode(t, resp)
	record := body["record"].(map[string]any)
	assert.Equal(t, true, record["is_verified"], "record must be marked verified")
	assert.NotEmpty(t, record["verified_at"])
	assert.NotEmpty(t, body["token"], "verified attestation must auto-issue a credential")
}

// TestAttestationOIDCVerifierRejectsUntrustedIssuer enforces the issuer
// allowlist: a perfectly-signed JWT from an issuer that is NOT in the
// tenant's policy must be rejected without ever fetching that issuer's JWKS.
func TestAttestationOIDCVerifierRejectsUntrustedIssuer(t *testing.T) {
	trusted := newOIDCIssuer(t)
	untrusted := newOIDCIssuer(t)
	defer trusted.close()
	defer untrusted.close()

	reg := registerAgent(t, uid("attest-oidc-untrusted"))
	upsertOIDCPolicy(t, map[string]any{
		"issuers": []map[string]any{{"url": trusted.URL}},
	})

	token := untrusted.sign(map[string]any{"sub": "attacker"})
	id := submitAttestation(t, reg.AgentID, "oidc_token", token)

	resp := verifyAttestation(t, id)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"JWT from an untrusted issuer must be rejected")
}

// TestAttestationOIDCVerifierRejectsTamperedSignature ensures the JWT
// signature is actually checked: flipping a byte in the signature segment
// must cause verification to fail even when the issuer is trusted.
func TestAttestationOIDCVerifierRejectsTamperedSignature(t *testing.T) {
	iss := newOIDCIssuer(t)
	defer iss.close()

	reg := registerAgent(t, uid("attest-oidc-tampered"))
	upsertOIDCPolicy(t, map[string]any{
		"issuers": []map[string]any{{"url": iss.URL}},
	})

	good := iss.sign(map[string]any{"sub": "ci-job-1"})
	// Flip the last signature byte — the token string format is
	// header.payload.signature.
	tampered := good[:len(good)-1] + flipLastByte(good)
	id := submitAttestation(t, reg.AgentID, "oidc_token", tampered)

	resp := verifyAttestation(t, id)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"tampered JWT must fail signature verification")
}

// TestAttestationOIDCVerifierRejectsExpired ensures the verifier enforces
// the JWT exp claim (exp in the past should reject).
func TestAttestationOIDCVerifierRejectsExpired(t *testing.T) {
	iss := newOIDCIssuer(t)
	defer iss.close()

	reg := registerAgent(t, uid("attest-oidc-expired"))
	upsertOIDCPolicy(t, map[string]any{
		"issuers": []map[string]any{{"url": iss.URL}},
	})

	// Mint a JWT that expired an hour ago by building it manually — we can't
	// easily override exp through the iss.sign helper, so do it inline.
	tok := jwt.New()
	require.NoError(t, tok.Set(jwt.IssuerKey, iss.URL))
	require.NoError(t, tok.Set(jwt.IssuedAtKey, time.Now().Add(-2*time.Hour).Unix()))
	require.NoError(t, tok.Set(jwt.ExpirationKey, time.Now().Add(-1*time.Hour).Unix()))
	require.NoError(t, tok.Set(jwt.SubjectKey, "ci-job-1"))
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, iss.signKey))
	require.NoError(t, err)

	id := submitAttestation(t, reg.AgentID, "oidc_token", string(signed))
	resp := verifyAttestation(t, id)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"expired JWT must be rejected")
}

// TestAttestationOIDCVerifierRejectsRequiredClaimMismatch verifies that the
// RequiredClaims binder actually runs — a token missing/mismatching a
// configured claim must fail even if signature + issuer + aud all pass.
func TestAttestationOIDCVerifierRejectsRequiredClaimMismatch(t *testing.T) {
	iss := newOIDCIssuer(t)
	defer iss.close()

	reg := registerAgent(t, uid("attest-oidc-claim"))
	upsertOIDCPolicy(t, map[string]any{
		"issuers": []map[string]any{{
			"url":             iss.URL,
			"required_claims": map[string]string{"repository": "myorg/myrepo"},
		}},
	})

	// Claim value is wrong (different repo).
	token := iss.sign(map[string]any{
		"sub":        "ci-job-1",
		"repository": "rogueorg/rogue",
	})
	id := submitAttestation(t, reg.AgentID, "oidc_token", token)

	resp := verifyAttestation(t, id)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"required_claims mismatch must reject the attestation")
}

// flipLastByte returns the last byte of s with a single bit flipped, so
// good[:len(good)-1] + flipLastByte(good) produces a JWT with a corrupted
// signature byte.
func flipLastByte(s string) string {
	b := []byte{s[len(s)-1]}
	b[0] ^= 0x01
	// base64url alphabet: keep it valid-looking so parsing gets past the
	// format check and hits actual signature verification.
	if b[0] == '.' || b[0] == '=' {
		b[0] = 'A'
	}
	return string(b)
}
