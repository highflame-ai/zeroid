package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// RefreshTokenService handles refresh token issuance and rotation.
type RefreshTokenService struct {
	repo *postgres.RefreshTokenRepository
	db   *bun.DB
}

// NewRefreshTokenService creates a new refresh token service.
func NewRefreshTokenService(repo *postgres.RefreshTokenRepository, db *bun.DB) *RefreshTokenService {
	return &RefreshTokenService{repo: repo, db: db}
}

// RefreshTokenParams contains the data needed to issue a refresh token.
type RefreshTokenParams struct {
	ClientID   string
	AccountID  string
	ProjectID  string
	UserID     string
	IdentityID *string
	Scopes     string
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

	ttl := time.Duration(domain.RefreshTokenTTLDays) * 24 * time.Hour
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
// Wrapped in a serializable transaction to prevent race conditions where two concurrent
// calls with the same token both succeed and issue duplicate tokens.
func (s *RefreshTokenService) RotateRefreshToken(ctx context.Context, rawToken string) (*domain.RefreshToken, *RefreshTokenResult, error) {
	tokenHash := hashRefreshToken(rawToken)

	var existing *domain.RefreshToken
	var result *RefreshTokenResult

	err := s.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		var err error

		// First check if this token exists at all (including revoked) for reuse detection.
		existing, err = s.repo.GetByTokenHashIncludingRevoked(ctx, tokenHash)
		if err != nil {
			return fmt.Errorf("refresh token not found: %w", err)
		}

		// Reuse detection: if the token was already revoked, someone is replaying it.
		// Revoke the entire family as a security measure.
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

		// Check expiry.
		if time.Now().After(existing.ExpiresAt) {
			return fmt.Errorf("refresh token expired")
		}

		// Revoke the current token (single-use rotation).
		if err := s.repo.RevokeByID(ctx, existing.ID); err != nil {
			return fmt.Errorf("failed to revoke old refresh token: %w", err)
		}

		// Issue a new token in the same family.
		newRawToken, err := generateRefreshToken()
		if err != nil {
			return fmt.Errorf("failed to generate new refresh token: %w", err)
		}

		newTokenHash := hashRefreshToken(newRawToken)

		ttl := time.Duration(domain.RefreshTokenTTLDays) * 24 * time.Hour
		expiresAt := time.Now().Add(ttl)

		newRecord := &domain.RefreshToken{
			TokenHash:  newTokenHash,
			ClientID:   existing.ClientID,
			AccountID:  existing.AccountID,
			ProjectID:  existing.ProjectID,
			UserID:     existing.UserID,
			IdentityID: existing.IdentityID,
			Scopes:     existing.Scopes,
			FamilyID:   existing.FamilyID, // Same family — rotation chain.
			State:      domain.RefreshTokenStateActive,
			ExpiresAt:  expiresAt,
		}

		if err := s.repo.Create(ctx, newRecord); err != nil {
			return fmt.Errorf("failed to store new refresh token: %w", err)
		}

		result = &RefreshTokenResult{
			RawToken:  newRawToken,
			FamilyID:  existing.FamilyID,
			ExpiresAt: expiresAt,
		}

		return nil
	})

	if err != nil {
		return nil, nil, err
	}

	return existing, result, nil
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
