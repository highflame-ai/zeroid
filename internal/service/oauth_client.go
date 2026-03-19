package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// ErrOAuthClientNotFound is returned when a client lookup fails.
var ErrOAuthClientNotFound = errors.New("oauth client not found")

// ErrOAuthClientAlreadyExists is returned when a client with the same client_id already exists.
var ErrOAuthClientAlreadyExists = errors.New("oauth client already exists")

// ErrInvalidClientSecret is returned when secret verification fails.
var ErrInvalidClientSecret = errors.New("invalid client secret")

// OAuthClientService manages OAuth2 client registration.
type OAuthClientService struct {
	repo *postgres.OAuthClientRepository
}

// NewOAuthClientService creates a new OAuthClientService.
func NewOAuthClientService(repo *postgres.OAuthClientRepository) *OAuthClientService {
	return &OAuthClientService{repo: repo}
}

// RegisterClient creates a new OAuth2 client, hashing the secret with bcrypt.
// Returns the created client with the plain-text secret (only shown once).
//
// externalID is used as the client_id (must match the identity's external_id
// so client_credentials grant can resolve the identity). identityID is the
// identity UUID to link to. Both are required.
func (s *OAuthClientService) RegisterClient(ctx context.Context, accountID, projectID, name string, grantTypes, scopes []string, externalID, identityID string) (*domain.OAuthClient, string, error) {
	if accountID == "" || projectID == "" || name == "" {
		return nil, "", fmt.Errorf("accountID, projectID, and name are required")
	}
	if externalID == "" || identityID == "" {
		return nil, "", fmt.Errorf("externalID and identityID are required")
	}

	plainSecret, err := generateSecureToken(32)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate client_secret: %w", err)
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(plainSecret), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", fmt.Errorf("failed to hash client secret: %w", err)
	}

	if len(grantTypes) == 0 {
		grantTypes = []string{"client_credentials"}
	}
	if len(scopes) == 0 {
		scopes = []string{}
	}

	now := time.Now()
	client := &domain.OAuthClient{
		ID:           uuid.New().String(),
		AccountID:    accountID,
		ProjectID:    projectID,
		ClientID:     externalID,
		ClientSecret: string(hashed),
		Name:         name,
		IdentityID:   identityID,
		GrantTypes:   grantTypes,
		RedirectURIs: []string{},
		Scopes:       scopes,
		IsActive:     true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.repo.Create(ctx, client); err != nil {
		if isDuplicateKeyError(err) {
			return nil, "", ErrOAuthClientAlreadyExists
		}
		return nil, "", fmt.Errorf("failed to register oauth client: %w", err)
	}

	log.Info().
		Str("client_id", externalID).
		Str("account_id", accountID).
		Str("project_id", projectID).
		Msg("OAuth2 client registered")

	return client, plainSecret, nil
}

// GetClient retrieves a client by UUID, scoped to tenant.
func (s *OAuthClientService) GetClient(ctx context.Context, id, accountID, projectID string) (*domain.OAuthClient, error) {
	client, err := s.repo.GetByID(ctx, id, accountID, projectID)
	if err != nil {
		return nil, ErrOAuthClientNotFound
	}
	return client, nil
}

// ListClients returns all clients for a tenant.
func (s *OAuthClientService) ListClients(ctx context.Context, accountID, projectID string) ([]*domain.OAuthClient, error) {
	return s.repo.List(ctx, accountID, projectID)
}

// VerifyClientSecret looks up a client by client_id within a tenant and verifies
// the provided secret against the bcrypt hash.
func (s *OAuthClientService) VerifyClientSecret(ctx context.Context, clientID, secret, accountID, projectID string) (*domain.OAuthClient, error) {
	client, err := s.repo.GetByClientID(ctx, clientID, accountID, projectID)
	if err != nil {
		return nil, ErrOAuthClientNotFound
	}
	if !client.IsActive {
		return nil, ErrOAuthClientNotFound
	}
	if err := bcrypt.CompareHashAndPassword([]byte(client.ClientSecret), []byte(secret)); err != nil {
		return nil, ErrInvalidClientSecret
	}
	return client, nil
}

// RotateSecret generates and stores a new secret for a client.
// Returns the new plain-text secret (only shown once).
func (s *OAuthClientService) RotateSecret(ctx context.Context, id, accountID, projectID string) (*domain.OAuthClient, string, error) {
	client, err := s.repo.GetByID(ctx, id, accountID, projectID)
	if err != nil {
		return nil, "", ErrOAuthClientNotFound
	}

	plainSecret, err := generateSecureToken(32)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate secret: %w", err)
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(plainSecret), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", fmt.Errorf("failed to hash secret: %w", err)
	}

	client.ClientSecret = string(hashed)
	client.UpdatedAt = time.Now()
	if err := s.repo.Update(ctx, client); err != nil {
		return nil, "", fmt.Errorf("failed to update client secret: %w", err)
	}

	return client, plainSecret, nil
}

// DeleteClient removes an OAuth2 client.
func (s *OAuthClientService) DeleteClient(ctx context.Context, id, accountID, projectID string) error {
	return s.repo.Delete(ctx, id, accountID, projectID)
}

// generateSecureToken creates a cryptographically random hex-encoded token.
func generateSecureToken(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}
	return hex.EncodeToString(b), nil
}
