package service

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
	"github.com/rs/zerolog/log"
)

type DownstreamTokenService struct {
	repo          *postgres.DownstreamTokenRepository
	encryptionKey []byte
}

func NewDownstreamTokenService(repo *postgres.DownstreamTokenRepository, encryptionKey []byte) *DownstreamTokenService {
	return &DownstreamTokenService{
		repo:          repo,
		encryptionKey: encryptionKey,
	}
}

// StoreTokenRequest is the input for storing a downstream token.
type StoreTokenRequest struct {
	AccessToken  string          `json:"access_token"`
	RefreshToken string          `json:"refresh_token,omitempty"`
	TokenType    string          `json:"token_type"`
	Scopes       string          `json:"scopes,omitempty"`
	ExpiresIn    *int            `json:"expires_in,omitempty"`
	OAuthConfig  json.RawMessage `json:"oauth_config,omitempty"`
}

// GetTokenResponse is the decrypted token returned to firehog.
type GetTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

// StoreToken encrypts and persists a downstream token.
func (s *DownstreamTokenService) StoreToken(
	ctx context.Context,
	accountID, projectID, userID, serverSlug string,
	req *StoreTokenRequest,
) error {
	encAccess, err := encryptGCM(req.AccessToken, s.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt access token: %w", err)
	}

	var encRefresh string
	if req.RefreshToken != "" {
		encRefresh, err = encryptGCM(req.RefreshToken, s.encryptionKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt refresh token: %w", err)
		}
	}

	var expiresAt *time.Time
	if req.ExpiresIn != nil && *req.ExpiresIn > 0 {
		t := time.Now().Add(time.Duration(*req.ExpiresIn) * time.Second)
		expiresAt = &t
	}

	tokenType := req.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}

	token := &domain.DownstreamToken{
		AccountID:    accountID,
		ProjectID:    projectID,
		UserID:       userID,
		ServerSlug:   serverSlug,
		AccessToken:  encAccess,
		RefreshToken: encRefresh,
		TokenType:    tokenType,
		Scopes:       req.Scopes,
		ExpiresAt:    expiresAt,
		OAuthConfig:  req.OAuthConfig,
		UpdatedAt:    time.Now(),
	}

	return s.repo.Upsert(ctx, token)
}

// GetToken retrieves and decrypts a downstream token. Auto-refreshes if expired.
func (s *DownstreamTokenService) GetToken(
	ctx context.Context,
	accountID, projectID, userID, serverSlug string,
) (*GetTokenResponse, error) {
	token, err := s.repo.Get(ctx, accountID, projectID, userID, serverSlug)
	if err != nil {
		return nil, err
	}

	// Auto-refresh if expired and refresh token exists
	if isExpired(token) && token.RefreshToken != "" {
		if refreshErr := s.tryRefresh(ctx, token); refreshErr != nil {
			log.Warn().Err(refreshErr).
				Str("server", serverSlug).
				Str("user", userID).
				Msg("token refresh failed")
		}
	}

	accessToken, err := decryptGCM(token.AccessToken, s.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt access token: %w", err)
	}

	return &GetTokenResponse{
		AccessToken: accessToken,
		TokenType:   token.TokenType,
	}, nil
}

// DeleteToken removes a downstream token.
func (s *DownstreamTokenService) DeleteToken(
	ctx context.Context,
	accountID, projectID, userID, serverSlug string,
) error {
	return s.repo.Delete(ctx, accountID, projectID, userID, serverSlug)
}

// ListByUser returns token statuses (no secrets) for a user.
func (s *DownstreamTokenService) ListByUser(
	ctx context.Context,
	accountID, projectID, userID string,
) ([]domain.DownstreamTokenStatus, error) {
	tokens, err := s.repo.ListByUser(ctx, accountID, projectID, userID)
	if err != nil {
		return nil, err
	}

	statuses := make([]domain.DownstreamTokenStatus, len(tokens))
	for i, t := range tokens {
		statuses[i] = domain.DownstreamTokenStatus{
			ServerSlug:  t.ServerSlug,
			UserID:      t.UserID,
			Connected:   true,
			TokenType:   t.TokenType,
			Scopes:      t.Scopes,
			ConnectedAt: t.CreatedAt.Format(time.RFC3339),
		}
	}
	return statuses, nil
}

func isExpired(token *domain.DownstreamToken) bool {
	if token.ExpiresAt == nil {
		return false
	}
	return time.Now().After(token.ExpiresAt.Add(-60 * time.Second))
}

func (s *DownstreamTokenService) tryRefresh(ctx context.Context, token *domain.DownstreamToken) error {
	if len(token.OAuthConfig) == 0 {
		return fmt.Errorf("no oauth config for refresh")
	}

	var oauthCfg struct {
		TokenURL     string `json:"token_url"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.Unmarshal(token.OAuthConfig, &oauthCfg); err != nil {
		return fmt.Errorf("failed to parse oauth config: %w", err)
	}
	if oauthCfg.TokenURL == "" {
		return fmt.Errorf("missing token_url in oauth config")
	}

	refreshToken, err := decryptGCM(token.RefreshToken, s.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt refresh token: %w", err)
	}

	// Exchange refresh token
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {oauthCfg.ClientID},
		"client_secret": {oauthCfg.ClientSecret},
	}

	resp, err := http.PostForm(oauthCfg.TokenURL, data)
	if err != nil {
		return fmt.Errorf("refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("refresh returned status %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to parse refresh response: %w", err)
	}

	// Encrypt new tokens
	encAccess, err := encryptGCM(tokenResp.AccessToken, s.encryptionKey)
	if err != nil {
		return err
	}
	token.AccessToken = encAccess

	if tokenResp.RefreshToken != "" {
		encRefresh, err := encryptGCM(tokenResp.RefreshToken, s.encryptionKey)
		if err != nil {
			return err
		}
		token.RefreshToken = encRefresh
	}

	if tokenResp.ExpiresIn > 0 {
		t := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
		token.ExpiresAt = &t
	}

	return s.repo.Update(ctx, token)
}

// AES-256-GCM encryption (compatible with admin's EncryptStringGCM)
func encryptGCM(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func decryptGCM(encrypted string, key []byte) (string, error) {
	enc, err := base64.URLEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := aesGCM.NonceSize()
	if len(enc) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

