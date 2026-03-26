package postgres

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
)

// OAuthClientRepository handles database operations for OAuth2 clients.
type OAuthClientRepository struct {
	db *bun.DB
}

// NewOAuthClientRepository creates a new OAuthClientRepository.
func NewOAuthClientRepository(db *bun.DB) *OAuthClientRepository {
	return &OAuthClientRepository{db: db}
}

// Create inserts a new OAuth2 client.
func (r *OAuthClientRepository) Create(ctx context.Context, client *domain.OAuthClient) error {
	_, err := r.db.NewInsert().Model(client).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to create oauth client: %w", err)
	}
	return nil
}

// GetByClientID retrieves a client by its globally unique OAuth2 client_id.
func (r *OAuthClientRepository) GetByClientID(ctx context.Context, clientID string) (*domain.OAuthClient, error) {
	client := &domain.OAuthClient{}
	err := r.db.NewSelect().Model(client).
		Where("client_id = ?", clientID).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get oauth client: %w", err)
	}
	return client, nil
}

// GetPublicByClientID retrieves a public client by its OAuth2 client_id only.
// Public PKCE clients are identified by client_type = 'public'.
func (r *OAuthClientRepository) GetPublicByClientID(ctx context.Context, clientID string) (*domain.OAuthClient, error) {
	client := &domain.OAuthClient{}
	err := r.db.NewSelect().Model(client).
		Where("client_id = ?", clientID).
		Where("client_type = ?", "public").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get public oauth client: %w", err)
	}
	return client, nil
}

// GetByID retrieves a client by its UUID.
func (r *OAuthClientRepository) GetByID(ctx context.Context, id string) (*domain.OAuthClient, error) {
	client := &domain.OAuthClient{}
	err := r.db.NewSelect().Model(client).
		Where("id = ?", id).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get oauth client: %w", err)
	}
	return client, nil
}

// List returns all registered OAuth2 clients.
func (r *OAuthClientRepository) List(ctx context.Context) ([]*domain.OAuthClient, error) {
	var clients []*domain.OAuthClient
	err := r.db.NewSelect().Model(&clients).
		OrderExpr("created_at DESC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list oauth clients: %w", err)
	}
	return clients, nil
}

// Update persists changes to an OAuth2 client.
func (r *OAuthClientRepository) Update(ctx context.Context, client *domain.OAuthClient) error {
	_, err := r.db.NewUpdate().Model(client).Where("id = ?", client.ID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to update oauth client: %w", err)
	}
	return nil
}

// Delete removes an OAuth2 client (hard delete — clients are admin-controlled).
func (r *OAuthClientRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.NewDelete().
		TableExpr("oauth_clients").
		Where("id = ?", id).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete oauth client: %w", err)
	}
	return nil
}
