package authjwt

import (
	"context"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/rs/zerolog"
)

var (
	ErrNoToken        = errors.New("authjwt: no token provided")
	ErrInvalidToken   = errors.New("authjwt: invalid token")
	ErrExpiredToken   = errors.New("authjwt: token expired")
	ErrInvalidIssuer  = errors.New("authjwt: invalid issuer")
	ErrUnsupportedAlg = errors.New("authjwt: unsupported signing algorithm")
	ErrNoKeySet       = errors.New("authjwt: no JWKS available")
)

// allowedAlgorithms restricts which signing algorithms are accepted.
// Prevents algorithm confusion attacks.
var allowedAlgorithms = map[jwa.SignatureAlgorithm]struct{}{
	jwa.RS256: {},
	jwa.ES256: {},
}

// Verifier validates ZeroID-issued JWTs using a remote JWKS.
type Verifier struct {
	jwks   *JWKSClient
	issuer string
	logger zerolog.Logger
}

// VerifierConfig configures a Verifier.
type VerifierConfig struct {
	// JWKSURL is the URL of the JWKS endpoint (e.g., "https://auth.example.com/.well-known/jwks.json").
	// Required.
	JWKSURL string

	// Issuer is the expected "iss" claim value. If set, tokens with a
	// different issuer are rejected. Recommended for production.
	Issuer string

	// Logger for verification events. Defaults to no-op.
	Logger zerolog.Logger

	// JWKSOptions are passed to the underlying JWKS client.
	JWKSOptions []JWKSOption
}

// NewVerifier creates a Verifier that validates tokens against a remote JWKS.
// Performs an initial synchronous JWKS fetch — returns error if unreachable.
// Call Close() to release resources.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	if cfg.JWKSURL == "" {
		return nil, fmt.Errorf("authjwt: JWKSURL is required")
	}

	opts := append(cfg.JWKSOptions, WithLogger(cfg.Logger))
	jwks, err := NewJWKSClient(cfg.JWKSURL, opts...)
	if err != nil {
		return nil, err
	}

	return &Verifier{
		jwks:   jwks,
		issuer: cfg.Issuer,
		logger: cfg.Logger,
	}, nil
}

// Verify parses and validates a JWT string, returning the extracted claims.
// It performs:
//  1. JWS signature verification against the cached JWKS (auto-matches kid+alg)
//  2. Algorithm allowlist check (RS256, ES256 only)
//  3. Standard claim validation (exp, iat, nbf)
//  4. Issuer verification (if configured)
//  5. On unknown kid: one-time JWKS refresh + retry (handles key rotation)
func (v *Verifier) Verify(ctx context.Context, tokenString string) (*Claims, error) {
	if tokenString == "" {
		return nil, ErrNoToken
	}

	claims, err := v.verify(ctx, tokenString)
	if err != nil {
		// If verification failed, check if it's a kid miss — try refreshing JWKS once.
		kid := extractKID(tokenString)
		if kid != "" && v.jwks.RefreshIfMissing(ctx, kid) {
			// Retry with refreshed key set.
			claims, err = v.verify(ctx, tokenString)
			if err != nil {
				return nil, err
			}
			return claims, nil
		}
		return nil, err
	}

	return claims, nil
}

func (v *Verifier) verify(ctx context.Context, tokenString string) (*Claims, error) {
	keySet := v.jwks.KeySet()
	if keySet == nil || keySet.Len() == 0 {
		return nil, ErrNoKeySet
	}

	// Parse and validate in one step. WithKeySet uses kid+alg to select the key.
	parseOpts := []jwt.ParseOption{
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
		jwt.WithContext(ctx),
	}
	if v.issuer != "" {
		parseOpts = append(parseOpts, jwt.WithIssuer(v.issuer))
	}

	token, err := jwt.Parse([]byte(tokenString), parseOpts...)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired()) {
			return nil, fmt.Errorf("%w: %v", ErrExpiredToken, err)
		}
		if errors.Is(err, jwt.ErrInvalidIssuer()) {
			return nil, fmt.Errorf("%w: %v", ErrInvalidIssuer, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	// Verify the algorithm is in our allowlist.
	if err := v.checkAlgorithm(tokenString); err != nil {
		return nil, err
	}

	return extractClaims(token), nil
}

// checkAlgorithm parses the JWS header to verify the algorithm is allowed.
// This is defense-in-depth — lestrrat-go/jwx already validates the signature
// against the key type, but we explicitly reject unexpected algorithms.
func (v *Verifier) checkAlgorithm(tokenString string) error {
	msg, err := jws.Parse([]byte(tokenString))
	if err != nil {
		return fmt.Errorf("%w: cannot parse JWS: %v", ErrInvalidToken, err)
	}
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return fmt.Errorf("%w: no signatures", ErrInvalidToken)
	}
	alg := sigs[0].ProtectedHeaders().Algorithm()
	if _, ok := allowedAlgorithms[alg]; !ok {
		return fmt.Errorf("%w: %s", ErrUnsupportedAlg, alg)
	}
	return nil
}

// Close releases resources held by the verifier (stops JWKS background refresh).
func (v *Verifier) Close() {
	v.jwks.Close()
}

// extractKID reads the kid from a JWT header without full parsing/validation.
func extractKID(tokenString string) string {
	msg, err := jws.Parse([]byte(tokenString))
	if err != nil {
		return ""
	}
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return ""
	}
	return sigs[0].ProtectedHeaders().KeyID()
}
