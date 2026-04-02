package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/uptrace/bun"
)

type DownstreamTokenRepository struct {
	db *bun.DB
}

func NewDownstreamTokenRepository(db *bun.DB) *DownstreamTokenRepository {
	return &DownstreamTokenRepository{db: db}
}

// Upsert stores or updates a downstream token for a user+server pair.
func (r *DownstreamTokenRepository) Upsert(ctx context.Context, token *domain.DownstreamToken) error {
	_, err := r.db.NewInsert().
		Model(token).
		On("CONFLICT (user_id, server_slug, account_id, project_id) DO UPDATE").
		Set("access_token = EXCLUDED.access_token").
		Set("refresh_token = EXCLUDED.refresh_token").
		Set("token_type = EXCLUDED.token_type").
		Set("scopes = EXCLUDED.scopes").
		Set("expires_at = EXCLUDED.expires_at").
		Set("oauth_config = EXCLUDED.oauth_config").
		Set("updated_at = EXCLUDED.updated_at").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to upsert downstream token: %w", err)
	}
	return nil
}

// Get retrieves a downstream token by user+server within a tenant.
func (r *DownstreamTokenRepository) Get(ctx context.Context, accountID, projectID, userID, serverSlug string) (*domain.DownstreamToken, error) {
	token := new(domain.DownstreamToken)
	err := r.db.NewSelect().
		Model(token).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Where("user_id = ?", userID).
		Where("server_slug = ?", serverSlug).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("downstream token not found: %w", err)
	}
	return token, nil
}

// Delete removes a downstream token.
func (r *DownstreamTokenRepository) Delete(ctx context.Context, accountID, projectID, userID, serverSlug string) error {
	result, err := r.db.NewDelete().
		Model((*domain.DownstreamToken)(nil)).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Where("user_id = ?", userID).
		Where("server_slug = ?", serverSlug).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete downstream token: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("downstream token not found")
	}
	return nil
}

// ListByUser returns all downstream tokens for a user (no secrets).
func (r *DownstreamTokenRepository) ListByUser(ctx context.Context, accountID, projectID, userID string) ([]*domain.DownstreamToken, error) {
	var tokens []*domain.DownstreamToken
	err := r.db.NewSelect().
		Model(&tokens).
		Column("id", "server_slug", "user_id", "token_type", "scopes", "created_at", "updated_at").
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Where("user_id = ?", userID).
		OrderExpr("created_at DESC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list downstream tokens: %w", err)
	}
	return tokens, nil
}

// Update updates the access/refresh token and expiry (for token refresh).
func (r *DownstreamTokenRepository) Update(ctx context.Context, token *domain.DownstreamToken) error {
	_, err := r.db.NewUpdate().
		Model(token).
		Set("access_token = ?", token.AccessToken).
		Set("refresh_token = ?", token.RefreshToken).
		Set("expires_at = ?", token.ExpiresAt).
		Set("updated_at = ?", time.Now()).
		Where("id = ?", token.ID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to update downstream token: %w", err)
	}
	return nil
}
