package service

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

// AuthCodeClaims holds the decoded claims from an authorization code JWT.
type AuthCodeClaims struct {
	JTI           string    // JWT ID (jti claim or derived hash)
	ExpiresAt     time.Time // Token expiration
	ClientID      string    // "cid" — Client application ID
	CodeChallenge string    // "cc"  — PKCE code challenge (S256)
	RedirectURI   string    // "ruri" — OAuth redirect URI
	Scopes        []string  // "scp" — Granted scopes
	UserID        string    // "uid" — User ID
	OrgID         string    // "oid" — Organization ID
	AccountID     string    // "aid" — Account ID
	ProjectID     string    // "pid" — Project ID (optional)

	// Resources is the consented RFC 8707 resource ceiling — "rsc"
	// (CAP-IDN-027). Optional: absent on every code issued before this
	// existed, and on any request that did not name a resource.
	//
	// A signed CLAIM rather than a database row, for the same reason Scopes
	// is one. Auth codes are stateless HS256 JWTs and the auth_codes table
	// is a replay-consumption ledger written at redemption, so there is no
	// code row at authorization time to persist onto. Granted scope and
	// granted resource are the same kind of fact — decided at authorize,
	// needed at redemption, and must not be client-tamperable — and the
	// signature already covering "scp" covers this at no extra cost.
	//
	// Capped at one value on the authorize leg
	// (maxAuthorizeResourceIndicators) but carried as a slice: cardinality
	// is a constant, not a shape, so raising the cap must not change what
	// is on the wire (ADR 0037 D2).
	Resources []string // "rsc" — consented resource ceiling (optional)
}

// decodeAuthCodeJWT verifies and decodes a stateless auth code JWT (HS256).
// Auth codes are signed with the shared secret and are short-lived (5 min).
func decodeAuthCodeJWT(code, hmacSecret, expectedIssuer string) (*AuthCodeClaims, error) {
	token, err := jwt.Parse([]byte(code),
		jwt.WithKey(jwa.HS256(), []byte(hmacSecret)),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("auth code validation failed: %w", err)
	}

	// jwx v4: Issuer / Subject / JwtID / Expiration return (value, present).
	iss, _ := token.Issuer()
	if iss != expectedIssuer {
		return nil, fmt.Errorf("auth code has invalid issuer: %s", iss)
	}

	sub, _ := token.Subject()
	if sub != "auth-code" {
		return nil, fmt.Errorf("auth code has invalid subject: %s", sub)
	}

	// Use the JWT's jti claim if present; otherwise derive a deterministic
	// identifier from the SHA-256 hash of the raw code string. This ensures
	// replay protection works even for auth codes issued without a jti.
	jti, _ := token.JwtID()
	if jti == "" {
		h := sha256.Sum256([]byte(code))
		jti = "derived:" + hex.EncodeToString(h[:])
	}

	exp, _ := token.Expiration()
	claims := &AuthCodeClaims{
		JTI:           jti,
		ExpiresAt:     exp,
		ClientID:      getStringClaim(token, "cid"),
		CodeChallenge: getStringClaim(token, "cc"),
		RedirectURI:   getStringClaim(token, "ruri"),
		UserID:        getStringClaim(token, "uid"),
		OrgID:         getStringClaim(token, "oid"),
		AccountID:     getStringClaim(token, "aid"),
		ProjectID:     getStringClaim(token, "pid"),
	}

	// Extract scopes array. jwx v4 dropped the untyped Token.Get; use the
	// generic accessor instead and accept either []any or []string shapes
	// for resilience against issuance-side changes.
	if scopes, err := jwt.Get[[]string](token, "scp"); err == nil {
		claims.Scopes = scopes
	} else if scopesRaw, err := jwt.Get[[]any](token, "scp"); err == nil {
		for _, s := range scopesRaw {
			if str, ok := s.(string); ok {
				claims.Scopes = append(claims.Scopes, str)
			}
		}
	}

	// Extract the consented resource ceiling (CAP-IDN-027).
	//
	// This one FAILS CLOSED, unlike `scp` above, which skips an element it
	// cannot read. The asymmetry is deliberate: an ABSENT ceiling means "none
	// was recorded", which permits the token request to bind to any resource it
	// names (CAP-IDN-026). So silently dropping an unreadable element would
	// WIDEN what the code allows — in the limit, a fully malformed claim would
	// read as no ceiling at all and hand back exactly the unconstrained binding
	// the ceiling exists to prevent. A skipped scope narrows; a skipped
	// resource does the opposite.
	//
	// The claim is server-minted under a signature we just verified, so a
	// malformed one is our own bug or a forgery attempt against a leaked HMAC
	// secret. Neither is input to tolerate.
	//
	// A bare string is accepted as a single-value ceiling. It is unambiguous,
	// it is what a JSON layer that collapses one-element arrays would produce,
	// and it is strictly NARROWER than the absent case — so tolerating it costs
	// nothing, while rejecting it would fail a flow for no security gain.
	//
	// Presence is tested with Has rather than by whether a typed read succeeds.
	// That distinction is the whole fix: `"rsc": null` is PRESENT but decodes to
	// nil through every typed accessor including jwt.Get[any], so a
	// read-succeeded test treats it as absent — i.e. as "no ceiling", the
	// permissive state. Same for `"rsc": []`, which reads as a valid empty
	// slice. Both are shapes we never mint, so reaching them means our own bug
	// or a forgery against a leaked HMAC secret, and both must fail rather than
	// quietly widen.
	if token.Has("rsc") {
		resources, err := decodeResourceCeiling(token)
		if err != nil {
			return nil, err
		}
		claims.Resources = resources
	}

	return claims, nil
}

// decodeResourceCeiling reads the `rsc` claim of a code that already carries it,
// and refuses every shape that would otherwise read as an empty ceiling.
//
// Callers must gate on token.Has("rsc") — this function treats "cannot read a
// ceiling" as an error, which is only correct once presence is established.
func decodeResourceCeiling(token jwt.Token) ([]string, error) {
	var out []string

	switch {
	case true:
		if v, err := jwt.Get[[]string](token, "rsc"); err == nil {
			out = v
			break
		}
		// A bare string is accepted as a single-value ceiling: unambiguous, what
		// a JSON layer collapsing one-element arrays produces, and strictly
		// NARROWER than the absent case — so tolerating it costs nothing while
		// rejecting it would fail a flow for no security gain.
		if v, err := jwt.Get[string](token, "rsc"); err == nil {
			out = []string{v}
			break
		}
		if raw, err := jwt.Get[[]any](token, "rsc"); err == nil {
			out = make([]string, 0, len(raw))
			for _, r := range raw {
				s, ok := r.(string)
				if !ok {
					return nil, fmt.Errorf(
						"auth code has a malformed rsc claim: element of type %T is not a string", r)
				}
				out = append(out, s)
			}
			break
		}
		// Present but unreadable as any accepted shape — an object, a number, a
		// bool, or JSON null.
		return nil, fmt.Errorf(
			"auth code has a malformed rsc claim: expected a string or an array of strings")
	}

	// Present but naming nothing. Distinct from absent, and NOT equivalent to
	// it: absent means the client may still bind at the token endpoint
	// (CAP-IDN-026), so silently accepting an empty ceiling here would convert
	// a corrupt consent record into an unconstrained one.
	if len(out) == 0 {
		return nil, fmt.Errorf(
			"auth code has an empty rsc claim: a recorded ceiling must name at least one resource")
	}

	// Re-validate on the way IN, not only on the way out. The ceiling was
	// checked at issuance, but that is a different process, possibly a
	// different release, and the values are about to be stamped into a signed
	// access token and enforced on by Shield. Without this, a ceiling of [""]
	// — which validateResourceIndicators explicitly rejects at issuance —
	// would mint a token bound to the empty string.
	if _, err := validateResourceIndicators(out); err != nil {
		return nil, fmt.Errorf("auth code has an invalid rsc claim: %w", err)
	}

	return out, nil
}

// getStringClaim extracts a string claim from a JWT token, returning empty string if not present.
// jwx v4: jwt.Get[string] replaces the v2 Token.Get + type assertion.
func getStringClaim(token jwt.Token, key string) string {
	if v, err := jwt.Get[string](token, key); err == nil {
		return v
	}
	return ""
}

// verifyCodeChallenge verifies the PKCE S256 challenge.
// challenge = base64url(sha256(verifier))
func verifyCodeChallenge(codeVerifier, codeChallenge string) bool {
	hash := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(hash[:])

	return computed == codeChallenge
}

// normalizeLoopback normalizes loopback URIs per RFC 8252.
// Treats 127.0.0.1 and localhost as equivalent for native app OAuth redirects.
func normalizeLoopback(uri string) string {
	return strings.Replace(uri, "://127.0.0.1:", "://localhost:", 1)
}

// AuthCodeTTL is the lifetime of an issued authorization code. RFC 6749
// §4.1.2 recommends a maximum of 10 minutes; the conventional value across
// mainstream OAuth providers is 5 minutes. Short TTL is the primary defense
// against code interception — once the code is in the browser URL bar it's
// already exposed to logs, referer headers, and extensions, so we want it
// useless quickly.
const AuthCodeTTL = 5 * time.Minute

// AuthCodeSubject is the JWT subject string decodeAuthCodeJWT requires. Hard-
// coded to bind the JWT shape to the auth-code grant — a token without this
// subject (e.g. a regular access token someone tries to replay as an auth
// code) is rejected before any tenant context is read.
const AuthCodeSubject = "auth-code"

// mintAuthCodeJWT is the symmetric counterpart to decodeAuthCodeJWT — it
// produces an HS256 JWT containing the AuthCodeClaims shape that the decoder
// reads. Pure function: no service receiver, no I/O, fully deterministic
// given inputs (except for the time-derived jti). Callers (currently
// OAuthService.IssueAuthCode) are responsible for validating the surrounding
// OAuth context (client registration, redirect-uri allow-list, S256-only
// challenge) before invoking the mint.
//
// The jti is derived from sha256(client_id|user_id|now-nano) — deterministic
// enough for debug-traceability across logs, unique enough that two near-
// simultaneous codes for the same client+user don't collide. zeroid's
// Consume uses jti as the single-use key, so uniqueness is the only
// correctness requirement.
func mintAuthCodeJWT(claims *AuthCodeClaims, hmacSecret, issuer string, now time.Time) (string, error) {
	if hmacSecret == "" {
		return "", fmt.Errorf("authcode mint: hmac secret is empty")
	}
	if issuer == "" {
		return "", fmt.Errorf("authcode mint: issuer is empty")
	}
	if claims == nil {
		return "", fmt.Errorf("authcode mint: claims are nil")
	}
	if claims.ClientID == "" || claims.CodeChallenge == "" || claims.RedirectURI == "" {
		return "", fmt.Errorf("authcode mint: client_id, code_challenge, redirect_uri are all required")
	}
	if claims.AccountID == "" {
		return "", fmt.Errorf("authcode mint: account_id is required")
	}

	jti := claims.JTI
	if jti == "" {
		seed := fmt.Sprintf("%s|%s|%d", claims.ClientID, claims.UserID, now.UnixNano())
		h := sha256.Sum256([]byte(seed))
		// 32 hex chars — collision-resistant and short enough to fit in
		// log lines without wrapping.
		jti = hex.EncodeToString(h[:16])
	}

	exp := claims.ExpiresAt
	if exp.IsZero() {
		exp = now.Add(AuthCodeTTL)
	}

	builder := jwt.NewBuilder().
		Issuer(issuer).
		Subject(AuthCodeSubject).
		JwtID(jti).
		IssuedAt(now).
		Expiration(exp).
		Claim("cid", claims.ClientID).
		Claim("cc", claims.CodeChallenge).
		Claim("ruri", claims.RedirectURI).
		Claim("aid", claims.AccountID)

	if claims.UserID != "" {
		builder = builder.Claim("uid", claims.UserID)
	}
	if claims.OrgID != "" {
		builder = builder.Claim("oid", claims.OrgID)
	}
	if claims.ProjectID != "" {
		builder = builder.Claim("pid", claims.ProjectID)
	}
	if len(claims.Scopes) > 0 {
		// Stored as []any so jwx v4 serializes a JSON array. The decoder
		// at decodeAuthCodeJWT accepts both []string and []any shapes
		// (resilience against issuance-side changes), but we emit []any
		// to match what JSON unmarshal naturally produces on the receive
		// side — keeps the round-trip lossless.
		anyScopes := make([]any, len(claims.Scopes))
		for i, s := range claims.Scopes {
			anyScopes[i] = s
		}
		builder = builder.Claim("scp", anyScopes)
	}
	if len(claims.Resources) > 0 {
		// Emitted as []any for the same round-trip reason as "scp" above, and
		// ALWAYS as an array even though the authorize leg caps the ceiling at
		// one value. Cardinality is a constant, not a shape (ADR 0037 D2):
		// raising the cap must not change the claim's serialization, or every
		// code minted before the change becomes a compatibility case.
		anyResources := make([]any, len(claims.Resources))
		for i, r := range claims.Resources {
			anyResources[i] = r
		}
		builder = builder.Claim("rsc", anyResources)
	}

	tok, err := builder.Build()
	if err != nil {
		return "", fmt.Errorf("authcode mint: jwt build failed: %w", err)
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256(), []byte(hmacSecret)))
	if err != nil {
		return "", fmt.Errorf("authcode mint: jwt sign failed: %w", err)
	}

	return string(signed), nil
}
