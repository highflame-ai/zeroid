package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/signing"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// ErrNonceReplayed is returned when a WPT nonce has already been used.
var ErrNonceReplayed = errors.New("proof token nonce already used")

// ProofService handles WIMSE Proof Token (WPT) generation and verification.
type ProofService struct {
	jwksSvc   *signing.JWKSService
	proofRepo *postgres.ProofRepository
	issuer    string
}

// NewProofService creates a new ProofService.
func NewProofService(jwksSvc *signing.JWKSService, proofRepo *postgres.ProofRepository, issuer string) *ProofService {
	return &ProofService{jwksSvc: jwksSvc, proofRepo: proofRepo, issuer: issuer}
}

// GenerateProofToken generates a per-request WIMSE Proof Token for a given identity and target audience.
// WPTs are short-lived (5 minutes) and bound to a specific audience URI.
// The nonce must be unique; duplicate nonces are rejected. The uniqueness guarantee is enforced
// atomically by the database UNIQUE constraint on the nonce column — no pre-check is needed.
func (s *ProofService) GenerateProofToken(ctx context.Context, identity *domain.Identity, audience, nonce string) (string, error) {
	now := time.Now()
	expiresAt := now.Add(5 * time.Minute)
	jti := uuid.New().String()

	token := jwt.New()
	_ = token.Set(jwt.IssuerKey, s.issuer)
	_ = token.Set(jwt.SubjectKey, identity.WIMSEURI)
	_ = token.Set(jwt.AudienceKey, []string{audience})
	_ = token.Set(jwt.IssuedAtKey, now)
	_ = token.Set(jwt.ExpirationKey, expiresAt)
	_ = token.Set(jwt.JwtIDKey, jti)
	_ = token.Set("nonce", nonce)
	_ = token.Set("account_id", identity.AccountID)
	_ = token.Set("project_id", identity.ProjectID)

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256, s.jwksSvc.PrivateKey()))
	if err != nil {
		return "", fmt.Errorf("failed to sign proof token: %w", err)
	}

	// Persist proof token record for nonce dedup and audit.
	pt := &domain.ProofToken{
		ID:         uuid.New().String(),
		IdentityID: identity.ID,
		AccountID:  identity.AccountID,
		ProjectID:  identity.ProjectID,
		JTI:        jti,
		Nonce:      nonce,
		Audience:   audience,
		IssuedAt:   now,
		ExpiresAt:  expiresAt,
		CreatedAt:  now,
	}
	if err := s.proofRepo.Create(ctx, pt); err != nil {
		// The DB UNIQUE constraint on nonce catches replay atomically.
		if isDuplicateKeyError(err) {
			return "", ErrNonceReplayed
		}
		return "", fmt.Errorf("failed to persist proof token: %w", err)
	}

	return string(signed), nil
}

// VerifyProofToken parses and validates a WIMSE Proof Token, then marks it as used to prevent replay.
func (s *ProofService) VerifyProofToken(ctx context.Context, tokenStr, expectedAudience string) (jwt.Token, error) {
	parsed, err := jwt.Parse([]byte(tokenStr),
		jwt.WithKey(jwa.ES256, s.jwksSvc.PublicKey()),
		jwt.WithValidate(true),
		jwt.WithAudience(expectedAudience),
	)
	if err != nil {
		return nil, fmt.Errorf("proof token validation failed: %w", err)
	}

	jti := parsed.JwtID()

	// Check if already used (single-use enforcement).
	pt, err := s.proofRepo.GetByJTI(ctx, jti)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup proof token: %w", err)
	}
	if pt.IsUsed {
		return nil, ErrNonceReplayed
	}

	// Mark as used atomically.
	if err := s.proofRepo.MarkUsed(ctx, jti); err != nil {
		return nil, fmt.Errorf("failed to mark proof token as used: %w", err)
	}

	return parsed, nil
}
