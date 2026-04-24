package integration_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
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

// assertErrorBodyContains reads the response body (non-destructively — the
// body is restored after inspection so tests can still decode it) and
// asserts that the error message inside includes substr. Covers the case
// where a test passed with the right status but the WRONG reason (e.g.
// DB blip 500 → 400 after wrapping); without a body check, those slip
// through.
func assertErrorBodyContains(t *testing.T, resp *http.Response, substr string) {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	// Put the bytes back so defer Close and any further decode still work.
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	assert.Containsf(t, string(raw), substr,
		"error response body must mention %q (got: %s)", substr, string(raw))
}

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
	iss := newOIDCIssuer(t)
	defer iss.close()

	reg := registerAgent(t, uid("attest-no-policy"))
	token := iss.sign(map[string]any{"sub": "ci-job-1"})
	id := submitAttestation(t, reg.AgentID, "oidc_token", token)

	resp := verifyAttestation(t, id)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"verify must fail closed when the tenant has no attestation policy")
	assertErrorBodyContains(t, resp, "no attestation policy configured")
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
	assertErrorBodyContains(t, resp, "issuer not in allowlist")
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
	// Either "malformed JWT" (base64 decode flagged the corruption) or
	// "token validation failed" (signature check flagged it) is an
	// acceptable rejection reason — both come from the OIDC verifier.
	assertErrorBodyContains(t, resp, "oidc verifier")
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
	assertErrorBodyContains(t, resp, "token validation failed")
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
	assertErrorBodyContains(t, resp, "required claim")
}

// TestAttestationDoubleVerifyIsRejected enforces the ErrAttestationAlreadyVerified
// guard: once a record has been verified (even once successfully), a second
// /verify on the same record must be rejected so a retry-after-partial-
// failure can't mint a second credential from a single proof.
func TestAttestationDoubleVerifyIsRejected(t *testing.T) {
	iss := newOIDCIssuer(t)
	defer iss.close()

	reg := registerAgent(t, uid("attest-double"))
	upsertOIDCPolicy(t, map[string]any{
		"issuers": []map[string]any{{"url": iss.URL}},
	})

	token := iss.sign(map[string]any{"sub": "ci-job-double"})
	id := submitAttestation(t, reg.AgentID, "oidc_token", token)

	first := verifyAttestation(t, id)
	require.Equal(t, http.StatusOK, first.StatusCode, "first verify expected 200")
	_ = first.Body.Close()

	second := verifyAttestation(t, id)
	defer func() { _ = second.Body.Close() }()
	assert.Equal(t, http.StatusConflict, second.StatusCode,
		"second verify on an already-verified record must be 409 Conflict")
	assertErrorBodyContains(t, second, "already verified")
}

// TestAttestationPolicyUpsertReactivatesDisabled verifies the upsert-against-
// inactive-row bug is fixed: disabling a policy via is_active=false and then
// PUTting a fresh config must update the row in place, not violate the
// unique constraint.
func TestAttestationPolicyUpsertReactivatesDisabled(t *testing.T) {
	iss := newOIDCIssuer(t)
	defer iss.close()

	// First create an active policy.
	upsertOIDCPolicy(t, map[string]any{
		"issuers": []map[string]any{{"url": iss.URL}},
	})

	// Soft-disable it.
	disabled := false
	disableResp := doRequest(t, http.MethodPut, adminPath("/attestation-policies"), map[string]any{
		"proof_type": "oidc_token",
		"config": map[string]any{
			"issuers": []map[string]any{{"url": iss.URL}},
		},
		"is_active": &disabled,
	}, adminHeaders())
	require.Equal(t, http.StatusOK, disableResp.StatusCode)
	_ = disableResp.Body.Close()

	// Now re-enable (or just upsert again). Before the fix this hit the
	// unique constraint because GetByTenantProofType filters is_active.
	enabled := true
	reenable := doRequest(t, http.MethodPut, adminPath("/attestation-policies"), map[string]any{
		"proof_type": "oidc_token",
		"config": map[string]any{
			"issuers": []map[string]any{{"url": iss.URL}},
		},
		"is_active": &enabled,
	}, adminHeaders())
	defer func() { _ = reenable.Body.Close() }()
	assert.Equal(t, http.StatusOK, reenable.StatusCode,
		"upserting an inactive policy must reactivate it, not 500 on unique constraint")
}

// TestAttestationPolicyRejectsNonHTTPSIssuer exercises the write-time config
// validator: an http://... issuer URL should be rejected before it's stored,
// because OIDC discovery over plaintext lets a network attacker swap JWKS.
func TestAttestationPolicyRejectsNonHTTPSIssuer(t *testing.T) {
	resp := doRequest(t, http.MethodPut, adminPath("/attestation-policies"), map[string]any{
		"proof_type": "oidc_token",
		"config": map[string]any{
			"issuers": []map[string]any{{"url": "http://plaintext.example.com"}},
		},
	}, adminHeaders())
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"non-https issuer URL must be rejected at write time with 400")
	assertErrorBodyContains(t, resp, "https")
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
