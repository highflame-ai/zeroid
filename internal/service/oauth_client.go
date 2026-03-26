package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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

// RegisterClientRequest holds all fields for creating an OAuth2 client.
// Confidential clients get a generated bcrypt secret; public clients have none.
type RegisterClientRequest struct {
	ClientID                string
	Name                    string
	Description             string
	Confidential            bool
	TokenEndpointAuthMethod string
	GrantTypes              []string
	Scopes                  []string
	RedirectURIs            []string
	AccessTokenTTL          int
	RefreshTokenTTL         int
	JWKSURI                 string
	JWKS                    json.RawMessage
	SoftwareID              string
	SoftwareVersion         string
	Contacts                []string
	Metadata                json.RawMessage
}

// RegisterClient creates a new OAuth2 client.
//
// If req.Confidential is true, a client_secret is generated and bcrypt-hashed;
// the plain-text secret is returned (shown once only). For public clients the
// returned secret string is empty.
//
// Identity link is resolved at token issuance time (client_credentials grant),
// not at registration time — matching industry standard (Auth0, Okta).
func (s *OAuthClientService) RegisterClient(ctx context.Context, req RegisterClientRequest) (*domain.OAuthClient, string, error) {
	if req.ClientID == "" || req.Name == "" {
		return nil, "", fmt.Errorf("clientID and name are required")
	}

	var plainSecret string
	var hashedSecret string
	var clientType string
	var authMethod string

	if req.Confidential {
		secret, err := generateSecureToken(32)
		if err != nil {
			return nil, "", fmt.Errorf("failed to generate client_secret: %w", err)
		}
		hashed, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
		if err != nil {
			return nil, "", fmt.Errorf("failed to hash client secret: %w", err)
		}
		plainSecret = secret
		hashedSecret = string(hashed)
		clientType = "confidential"
		authMethod = "client_secret_basic"
	} else {
		clientType = "public"
		authMethod = "none"
	}

	if req.TokenEndpointAuthMethod != "" {
		authMethod = req.TokenEndpointAuthMethod
	}

	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		if req.Confidential {
			grantTypes = []string{"client_credentials"}
		} else {
			grantTypes = []string{"authorization_code"}
		}
	}

	redirectURIs := req.RedirectURIs
	if redirectURIs == nil {
		redirectURIs = []string{}
	}
	scopes := req.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	contacts := req.Contacts
	if contacts == nil {
		contacts = []string{}
	}

	now := time.Now()
	client := &domain.OAuthClient{
		ID:                      uuid.New().String(),
		ClientID:                req.ClientID,
		ClientSecret:            hashedSecret,
		Name:                    req.Name,
		Description:             req.Description,
		ClientType:              clientType,
		TokenEndpointAuthMethod: authMethod,
		GrantTypes:              grantTypes,
		RedirectURIs:            redirectURIs,
		Scopes:                  scopes,
		AccessTokenTTL:          req.AccessTokenTTL,
		RefreshTokenTTL:         req.RefreshTokenTTL,
		JWKSURI:                 req.JWKSURI,
		JWKS:                    req.JWKS,
		SoftwareID:              req.SoftwareID,
		SoftwareVersion:         req.SoftwareVersion,
		Contacts:                contacts,
		Metadata:                req.Metadata,
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
		Str("client_id", req.ClientID).
		Str("client_type", clientType).
		Msg("OAuth2 client registered")

	return client, plainSecret, nil
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

// GetClientByClientID retrieves any client (public or confidential) by client_id.
func (s *OAuthClientService) GetClientByClientID(ctx context.Context, clientID string) (*domain.OAuthClient, error) {
	client, err := s.repo.GetByClientID(ctx, clientID)
	if err != nil {
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

// UpdateClient persists changes to a client record.
func (s *OAuthClientService) UpdateClient(ctx context.Context, client *domain.OAuthClient) error {
	return s.repo.Update(ctx, client)
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
