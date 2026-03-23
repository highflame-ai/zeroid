package handler

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/internal/service"
)

// ── OAuth types ──────────────────────────────────────────────────────────────

type TokenInput struct {
	Body struct {
		GrantType    string `json:"grant_type" required:"true" doc:"OAuth grant type"`
		ClientID     string `json:"client_id,omitempty" doc:"OAuth client ID"`
		ClientSecret string `json:"client_secret,omitempty" doc:"OAuth client secret"`
		Scope        string `json:"scope,omitempty" doc:"Requested scopes (space-delimited)"`
		AccountID    string `json:"account_id,omitempty" doc:"Tenant account ID"`
		ProjectID    string `json:"project_id,omitempty" doc:"Tenant project ID"`
		Subject      string `json:"subject,omitempty" doc:"JWT assertion for jwt_bearer grant"`
		APIKey       string `json:"api_key,omitempty" doc:"zid_sk_* API key for api_key grant"`
		// token_exchange (RFC 8693) fields:
		SubjectToken     string `json:"subject_token,omitempty" doc:"Subject token being exchanged"`
		SubjectTokenType string `json:"subject_token_type,omitempty" doc:"RFC 8693 subject token type URI"`
		ActorToken       string `json:"actor_token,omitempty" doc:"Actor token for NHI delegation"`
		// External principal exchange fields (via trusted service):
		UserID        string `json:"user_id,omitempty" doc:"External user ID (for external principal exchange)"`
		UserEmail     string `json:"user_email,omitempty" doc:"User email (for external principal exchange)"`
		UserName      string `json:"user_name,omitempty" doc:"User display name (for external principal exchange)"`
		ApplicationID string `json:"application_id,omitempty" doc:"Application scope (for external principal exchange)"`
		// AdditionalClaims allows callers to inject arbitrary claims into the issued JWT.
		// Keys must not collide with standard OAuth/ZeroID claims. Values are set as-is.
		AdditionalClaims map[string]any `json:"additional_claims,omitempty" doc:"Arbitrary claims to include in the issued JWT"`
		// authorization_code grant fields:
		Code         string `json:"code,omitempty" doc:"Authorization code JWT"`
		CodeVerifier string `json:"code_verifier,omitempty" doc:"PKCE S256 code verifier"`
		RedirectURI  string `json:"redirect_uri,omitempty" doc:"OAuth redirect URI"`
		// refresh_token grant fields:
		RefreshToken string `json:"refresh_token,omitempty" doc:"Refresh token (zid_rt_*)"`
	}
}

type TokenOutput struct {
	Status int
	Body   any // domain.AccessToken on success; oauthErrorBody on error
}

// oauthErrorBody is the RFC 6749 §5.2 token error response.
type oauthErrorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// extractOAuthError maps a service-layer error to an OAuth 2.0 error code,
// description, and HTTP status per RFC 6749 §5.2.
func extractOAuthError(err error) (code, description string, status int) {
	// Structured OAuthError from the service layer — preferred path.
	var oauthErr *service.OAuthError
	if errors.As(err, &oauthErr) {
		return oauthErr.Code, oauthErr.Description, oauthErr.HTTPStatus
	}
	// Sentinel errors from deeper service layers (credential, policy).
	if errors.Is(err, service.ErrPolicyViolation) {
		return "policy_violation", err.Error(), http.StatusBadRequest
	}
	if errors.Is(err, service.ErrScopesNotAllowed) {
		return "insufficient_scope", err.Error(), http.StatusBadRequest
	}
	return "server_error", "an unexpected error occurred", http.StatusInternalServerError
}

type IntrospectInput struct {
	Body struct {
		Token string `json:"token" required:"true" minLength:"1" doc:"JWT to introspect"`
	}
}

type IntrospectOutput struct {
	Body any // dynamic shape per RFC 7662
}

type OAuthRevokeInput struct {
	Body struct {
		Token string `json:"token" required:"true" minLength:"1" doc:"JWT to revoke"`
	}
}

type OAuthRevokeOutput struct {
	Body struct {
		Revoked bool `json:"revoked"`
	}
}

// ── OAuth routes ─────────────────────────────────────────────────────────────

func (a *API) registerOAuthRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "oauth-token",
		Method:      http.MethodPost,
		Path:        "/oauth2/token",
		Summary:     "OAuth 2.0 Token Endpoint (client_credentials, jwt_bearer, token_exchange)",
		Description: "Publicly accessible — tenant is derived from credential material, not headers.",
		Tags:        []string{"OAuth"},
	}, a.tokenOp)

	huma.Register(api, huma.Operation{
		OperationID: "oauth-introspect",
		Method:      http.MethodPost,
		Path:        "/oauth2/token/introspect",
		Summary:     "Token Introspection (RFC 7662)",
		Tags:        []string{"OAuth"},
	}, a.introspectOp)

	huma.Register(api, huma.Operation{
		OperationID: "oauth-revoke",
		Method:      http.MethodPost,
		Path:        "/oauth2/token/revoke",
		Summary:     "Token Revocation (RFC 7009)",
		Description: "Always returns 200 per RFC 7009 §2.2.",
		Tags:        []string{"OAuth"},
	}, a.revokeOp)

	huma.Register(api, huma.Operation{
		OperationID:   "oauth-bc-authorize",
		Method:        http.MethodPost,
		Path:          "/oauth2/bc-authorize",
		Summary:       "CIBA Backchannel Authorization (human-in-the-loop approval)",
		Tags:          []string{"OAuth"},
		DefaultStatus: http.StatusNotImplemented,
	}, a.bcAuthorizeOp)
}

func (a *API) tokenOp(ctx context.Context, input *TokenInput) (*TokenOutput, error) {
	accessToken, err := a.oauthSvc.Token(ctx, service.TokenRequest{
		GrantType:        input.Body.GrantType,
		ClientID:         input.Body.ClientID,
		ClientSecret:     input.Body.ClientSecret,
		Scope:            input.Body.Scope,
		AccountID:        input.Body.AccountID,
		ProjectID:        input.Body.ProjectID,
		Subject:          input.Body.Subject,
		APIKey:           input.Body.APIKey,
		SubjectToken:     input.Body.SubjectToken,
		SubjectTokenType: input.Body.SubjectTokenType,
		ActorToken:       input.Body.ActorToken,
		UserID:           input.Body.UserID,
		UserEmail:        input.Body.UserEmail,
		UserName:         input.Body.UserName,
		ApplicationID:    input.Body.ApplicationID,
		AdditionalClaims: input.Body.AdditionalClaims,
		Code:             input.Body.Code,
		CodeVerifier:     input.Body.CodeVerifier,
		RedirectURI:      input.Body.RedirectURI,
		RefreshTokenStr:  input.Body.RefreshToken,
	})
	if err != nil {
		log.Error().Err(err).Str("grant_type", input.Body.GrantType).Msg("oauth token request failed")
		code, desc, status := extractOAuthError(err)
		return &TokenOutput{
			Status: status,
			Body:   oauthErrorBody{Error: code, ErrorDescription: desc},
		}, nil
	}

	return &TokenOutput{Status: http.StatusOK, Body: accessToken}, nil
}

func (a *API) introspectOp(ctx context.Context, input *IntrospectInput) (*IntrospectOutput, error) {
	result, err := a.oauthSvc.Introspect(ctx, input.Body.Token)
	if err != nil {
		return &IntrospectOutput{Body: map[string]any{"active": false}}, nil
	}

	return &IntrospectOutput{Body: result}, nil
}

func (a *API) revokeOp(ctx context.Context, input *OAuthRevokeInput) (*OAuthRevokeOutput, error) {
	_ = a.oauthSvc.Revoke(ctx, input.Body.Token)
	out := &OAuthRevokeOutput{}
	out.Body.Revoked = true
	return out, nil
}

func (a *API) bcAuthorizeOp(_ context.Context, _ *struct{}) (*struct{}, error) {
	return nil, huma.Error501NotImplemented("CIBA not yet implemented")
}
