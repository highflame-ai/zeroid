package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// RefreshTokenService handles refresh token issuance and rotation.
type RefreshTokenService struct {
	repo *postgres.RefreshTokenRepository
}

// NewRefreshTokenService creates a new refresh token service.
func NewRefreshTokenService(repo *postgres.RefreshTokenRepository) *RefreshTokenService {
	return &RefreshTokenService{repo: repo}
}

// RefreshTokenParams contains the data needed to issue a refresh token.
type RefreshTokenParams struct {
	ClientID   string
	AccountID  string
	ProjectID  string
	UserID     string
	IdentityID *string
	Scopes     string
	TTL        int // seconds, 0 = use default (90 days)
}

// RefreshTokenResult contains both the raw token (returned to client) and stored metadata.
type RefreshTokenResult struct {
	RawToken  string    // Returned to client once — never stored.
	FamilyID  string    // For audit/debugging.
	ExpiresAt time.Time
}

// IssueRefreshToken generates a new refresh token and starts a new token family.
func (s *RefreshTokenService) IssueRefreshToken(ctx context.Context, params *RefreshTokenParams) (*RefreshTokenResult, error) {
	rawToken, err := generateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	tokenHash := hashRefreshToken(rawToken)
	familyID := uuid.New().String()

	var ttl time.Duration
	if params.TTL > 0 {
		ttl = time.Duration(params.TTL) * time.Second
	} else {
		ttl = time.Duration(domain.RefreshTokenTTLDays) * 24 * time.Hour
	}

	expiresAt := time.Now().Add(ttl)

	record := &domain.RefreshToken{
		TokenHash:  tokenHash,
		ClientID:   params.ClientID,
		AccountID:  params.AccountID,
		ProjectID:  params.ProjectID,
		UserID:     params.UserID,
		IdentityID: params.IdentityID,
		Scopes:     params.Scopes,
		FamilyID:   familyID,
		State:      domain.RefreshTokenStateActive,
		ExpiresAt:  expiresAt,
	}

	if err := s.repo.Create(ctx, record); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return &RefreshTokenResult{
		RawToken:  rawToken,
		FamilyID:  familyID,
		ExpiresAt: expiresAt,
	}, nil
}

// RotateRefreshToken validates the presented token, revokes it, and issues a new one.
// Implements reuse detection: if a revoked token is presented, the entire family is revoked.
//
// Atomicity: the claim-and-revoke step is a single UPDATE ... WHERE state='active'
// RETURNING in postgres/refresh_token.go. Postgres row-level locking guarantees
// that exactly one concurrent caller wins, so two rotations racing on the same
// input cannot both produce successor tokens.
func (s *RefreshTokenService) RotateRefreshToken(ctx context.Context, rawToken string, ttl int) (*domain.RefreshToken, *RefreshTokenResult, error) {
	tokenHash := hashRefreshToken(rawToken)

	// Atomic claim: revokes the token iff it is currently active and non-expired,
	// returning the row on success.
	claimed, err := s.repo.ClaimByTokenHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, s.handleFailedClaim(ctx, tokenHash)
		}
		return nil, nil, fmt.Errorf("failed to claim refresh token: %w", err)
	}

	newRawToken, err := generateRefreshToken()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate new refresh token: %w", err)
	}

	newTokenHash := hashRefreshToken(newRawToken)

	var rotationTTL time.Duration
	if ttl > 0 {
		rotationTTL = time.Duration(ttl) * time.Second
	} else {
		rotationTTL = time.Duration(domain.RefreshTokenTTLDays) * 24 * time.Hour
	}

	expiresAt := time.Now().Add(rotationTTL)

	newRecord := &domain.RefreshToken{
		TokenHash:  newTokenHash,
		ClientID:   claimed.ClientID,
		AccountID:  claimed.AccountID,
		ProjectID:  claimed.ProjectID,
		UserID:     claimed.UserID,
		IdentityID: claimed.IdentityID,
		Scopes:     claimed.Scopes,
		FamilyID:   claimed.FamilyID, // Same family — rotation chain.
		State:      domain.RefreshTokenStateActive,
		ExpiresAt:  expiresAt,
	}

	if err := s.repo.Create(ctx, newRecord); err != nil {
		return nil, nil, fmt.Errorf("failed to store new refresh token: %w", err)
	}

	return claimed, &RefreshTokenResult{
		RawToken:  newRawToken,
		FamilyID:  claimed.FamilyID,
		ExpiresAt: expiresAt,
	}, nil
}

// handleFailedClaim runs when ClaimByTokenHash found no matching active,
// non-expired row. It disambiguates between reuse (revoked → trigger family
// revocation), expired, and not-found, returning the appropriate error.
func (s *RefreshTokenService) handleFailedClaim(ctx context.Context, tokenHash string) error {
	existing, err := s.repo.GetByTokenHashIncludingRevoked(ctx, tokenHash)
	if err != nil {
		return fmt.Errorf("refresh token not found: %w", err)
	}

	if existing.State == domain.RefreshTokenStateRevoked {
		count, revokeErr := s.repo.RevokeFamily(ctx, existing.FamilyID)
		log.Warn().
			Str("family_id", existing.FamilyID).
			Str("user_id", existing.UserID).
			Str("client_id", existing.ClientID).
			Int64("revoked_count", count).
			Err(revokeErr).
			Msg("Refresh token reuse detected — entire family revoked")
		return fmt.Errorf("refresh token reuse detected — family revoked")
	}

	if time.Now().After(existing.ExpiresAt) {
		return fmt.Errorf("refresh token expired")
	}

	// Should be unreachable: state is active and not expired, but ClaimByTokenHash
	// returned no row. Indicates clock skew or a concurrent state transition we
	// did not anticipate. Log loudly.
	log.Error().
		Str("family_id", existing.FamilyID).
		Str("state", existing.State).
		Time("expires_at", existing.ExpiresAt).
		Msg("Refresh token claim failed but lookup shows active non-expired token")
	return fmt.Errorf("refresh token in unexpected state")
}

// RevokeFamily revokes all active tokens in a refresh token family.
// Used during auth code replay detection per RFC 6749 §4.1.2.
func (s *RefreshTokenService) RevokeFamily(ctx context.Context, familyID string) (int64, error) {
	return s.repo.RevokeFamily(ctx, familyID)
}

// generateRefreshToken creates a cryptographically random refresh token.
// Format: zid_rt_<base64url(32 random bytes)>
func generateRefreshToken() (string, error) {
	b := make([]byte, domain.RefreshTokenByteLength)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return domain.RefreshTokenPrefix + "_" + base64.RawURLEncoding.EncodeToString(b), nil
}

// hashRefreshToken computes the SHA256 hex digest of a raw token.
func hashRefreshToken(rawToken string) string {
	h := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(h[:])
}
