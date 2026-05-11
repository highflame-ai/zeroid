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

	return claims, nil
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
