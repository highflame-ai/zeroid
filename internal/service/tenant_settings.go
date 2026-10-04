package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// ErrInvalidTokenProfile is returned when a caller names a token profile ZeroID
// does not support.
var ErrInvalidTokenProfile = errors.New("token_profile must be legacy or rfc8693")

// TenantSettingsService resolves and updates per-tenant settings.
type TenantSettingsService struct {
	repo *postgres.TenantSettingsRepository
}

// NewTenantSettingsService creates a new TenantSettingsService.
func NewTenantSettingsService(repo *postgres.TenantSettingsRepository) *TenantSettingsService {
	return &TenantSettingsService{repo: repo}
}

// TokenProfile returns the token profile the tenant's tokens are issued in.
// A tenant with no settings row is on the legacy profile.
//
// Read on every issuance, with no cache: a cache would make a profile switch
// take effect at different times on different replicas, and a token minted in
// the old shape after the switch is exactly the inconsistency a staged rollout
// has to rule out. The lookup is one primary-key read.
//
// An error is returned rather than defaulting to legacy, so a database fault
// fails the issuance instead of silently minting in the wrong shape.
func (s *TenantSettingsService) TokenProfile(ctx context.Context, accountID, projectID string) (domain.TokenProfile, error) {
	if s == nil || s.repo == nil {
		return domain.TokenProfileLegacy, nil
	}
	settings, err := s.repo.Get(ctx, accountID, projectID)
	if err != nil {
		return "", fmt.Errorf("resolve token profile: %w", err)
	}
	if settings == nil {
		return domain.TokenProfileLegacy, nil
	}
	return settings.TokenProfile, nil
}

// Get returns the tenant's settings with defaults filled in for a tenant that
// has no row, so callers always see the effective values.
func (s *TenantSettingsService) Get(ctx context.Context, accountID, projectID string) (*domain.TenantSettings, error) {
	settings, err := s.repo.Get(ctx, accountID, projectID)
	if err != nil {
		return nil, err
	}
	if settings == nil {
		return &domain.TenantSettings{
			AccountID:    accountID,
			ProjectID:    projectID,
			TokenProfile: domain.TokenProfileLegacy,
		}, nil
	}
	return settings, nil
}

// SetTokenProfile switches the tenant's token profile. Tokens already issued
// keep the shape they were minted in until they expire; only new issuance
// changes.
func (s *TenantSettingsService) SetTokenProfile(ctx context.Context, accountID, projectID string, profile domain.TokenProfile) (*domain.TenantSettings, error) {
	if !profile.IsValid() {
		return nil, fmt.Errorf("%w (got %q)", ErrInvalidTokenProfile, profile)
	}
	settings := &domain.TenantSettings{
		AccountID:    accountID,
		ProjectID:    projectID,
		TokenProfile: profile,
	}
	if err := s.repo.UpsertTokenProfile(ctx, settings); err != nil {
		return nil, err
	}
	return settings, nil
}
