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
	// credentials revokes the long-lived user-subject roots a switch to the
	// rfc8693 profile must not leave behind. Wired once at construction.
	credentials *CredentialService
}

// SetCredentialService wires the credential service the profile switch uses.
func (s *TenantSettingsService) SetCredentialService(cs *CredentialService) {
	s.credentials = cs
}

// UserAccessTokenMaxTTLSeconds is the longest lifetime a user-subject access
// token keeps across a switch to the rfc8693 profile: the short default every
// such token now gets (D14). Longer ones are revoked at the switch.
const UserAccessTokenMaxTTLSeconds = defaultUserAccessTokenTTL

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
// keep the shape they were minted in until they expire, with one exception:
// setting rfc8693 revokes the tenant's long-lived user-subject access tokens
// (D14), and returns how many credentials that revoked. The revocation runs
// every time rfc8693 is set, not only on the transition, so a request that
// switched the profile but failed part-way through revoking is completed by
// simply repeating it.
func (s *TenantSettingsService) SetTokenProfile(ctx context.Context, accountID, projectID string, profile domain.TokenProfile) (*domain.TenantSettings, int, error) {
	if !profile.IsValid() {
		return nil, 0, fmt.Errorf("%w (got %q)", ErrInvalidTokenProfile, profile)
	}
	settings := &domain.TenantSettings{
		AccountID:    accountID,
		ProjectID:    projectID,
		TokenProfile: profile,
	}
	if err := s.repo.UpsertTokenProfile(ctx, settings); err != nil {
		return nil, 0, err
	}
	revoked := 0
	if profile == domain.TokenProfileRFC8693 && s.credentials != nil {
		n, err := s.credentials.RevokeLongLivedUserAccessTokens(ctx, accountID, projectID, UserAccessTokenMaxTTLSeconds, "token_profile_switch")
		revoked = n
		if err != nil {
			return settings, revoked, fmt.Errorf("token profile set to rfc8693, but revoking long-lived user access tokens failed (repeat the request to finish): %w", err)
		}
	}
	return settings, revoked, nil
}
