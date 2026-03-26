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

// RegisterClient creates a new confidential OAuth2 client (M2M flows).
// Generates and bcrypt-hashes a client secret.
// Returns the created client and the plain-text secret (shown once only).
// Identity link is resolved at token issuance time (client_credentials grant),
// not at registration time — matching industry standard (Auth0, Okta).
func (s *OAuthClientService) RegisterClient(ctx context.Context, clientID, name string, grantTypes, scopes []string) (*domain.OAuthClient, string, error) {
	if clientID == "" || name == "" {
		return nil, "", fmt.Errorf("clientID and name are required")
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
		ClientID:     clientID,
		ClientSecret: string(hashed),
		Name:                    name,
		ClientType:              "confidential",
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              grantTypes,
		RedirectURIs:            []string{},
		Scopes:                  scopes,
		IsActive:                true,
		CreatedAt:               now,
		UpdatedAt:               now,
	}

	if err := s.repo.Create(ctx, client); err != nil {
		if isDuplicateKeyError(err) {
			return nil, "", ErrOAuthClientAlreadyExists
		}
		return nil, "", fmt.Errorf("failed to register oauth client: %w", err)
	}

	log.Info().
		Str("client_id", clientID).
		Msg("OAuth2 confidential client registered")

	return client, plainSecret, nil
}

// RegisterPublicClient creates a public OAuth2 client for user-facing flows
// (authorization_code + PKCE). Public clients have no client_secret and no
// linked agent identity — the user authenticates separately.
//
// clientID is the string the client presents in the authorization_code exchange.
// Token issuance behaviour is derived from grant_types: clients registered with
// "refresh_token" receive short-lived (1h) access tokens plus rotating refresh
// tokens; clients without it receive long-lived (90-day) tokens.
func (s *OAuthClientService) RegisterPublicClient(ctx context.Context, name, clientID string, redirectURIs, grantTypes, scopes []string) (*domain.OAuthClient, error) {
	if name == "" || clientID == "" {
		return nil, fmt.Errorf("name and clientID are required")
	}
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code"}
	}
	if redirectURIs == nil {
		redirectURIs = []string{}
	}
	if scopes == nil {
		scopes = []string{}
	}

	now := time.Now()
	client := &domain.OAuthClient{
		ID:                      uuid.New().String(),
		ClientID:                clientID,
		ClientSecret:            "", // public client — no secret
		Name:                    name,
		ClientType:              "public",
		TokenEndpointAuthMethod: "none",
		GrantTypes:              grantTypes,
		RedirectURIs:            redirectURIs,
		Scopes:                  scopes,
		IsActive:                true,
		CreatedAt:               now,
		UpdatedAt:               now,
	}

	if err := s.repo.Create(ctx, client); err != nil {
		if isDuplicateKeyError(err) {
			return nil, ErrOAuthClientAlreadyExists
		}
		return nil, fmt.Errorf("failed to register public client: %w", err)
	}

	log.Info().
		Str("client_id", clientID).
		Msg("OAuth2 public client registered (global)")

	return client, nil
}

// GetPublicClient retrieves a registered public PKCE client by client_id.
func (s *OAuthClientService) GetPublicClient(ctx context.Context, clientID string) (*domain.OAuthClient, error) {
	client, err := s.repo.GetPublicByClientID(ctx, clientID)
	if err != nil {
		return nil, ErrOAuthClientNotFound
	}
	if !client.IsActive {
		return nil, ErrOAuthClientNotFound
	}
	return client, nil
}

// GetClient retrieves a client by UUID.
func (s *OAuthClientService) GetClient(ctx context.Context, id string) (*domain.OAuthClient, error) {
	client, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, ErrOAuthClientNotFound
	}
	return client, nil
}

// ListClients returns all registered OAuth2 clients.
func (s *OAuthClientService) ListClients(ctx context.Context) ([]*domain.OAuthClient, error) {
	return s.repo.List(ctx)
}

// VerifyClientSecret looks up a client by client_id and verifies the provided
// secret against the bcrypt hash.
func (s *OAuthClientService) VerifyClientSecret(ctx context.Context, clientID, secret string) (*domain.OAuthClient, error) {
	client, err := s.repo.GetByClientID(ctx, clientID)
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
func (s *OAuthClientService) RotateSecret(ctx context.Context, id string) (*domain.OAuthClient, string, error) {
	client, err := s.repo.GetByID(ctx, id)
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
func (s *OAuthClientService) DeleteClient(ctx context.Context, id string) error {
	return s.repo.Delete(ctx, id)
}

// generateSecureToken creates a cryptographically random hex-encoded token.
func generateSecureToken(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}
	return hex.EncodeToString(b), nil
}
