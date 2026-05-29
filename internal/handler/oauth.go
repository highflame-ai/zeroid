package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	internalMiddleware "github.com/highflame-ai/zeroid/internal/middleware"
	"github.com/highflame-ai/zeroid/internal/oautherror"
	"github.com/highflame-ai/zeroid/internal/service"
)

// ── OAuth types ──────────────────────────────────────────────────────────────

type TokenInput struct {
	// DPoPProof carries the RFC 9449 proof-of-possession JWT. When non-empty,
	// the issued token is bound to the proof key (cnf.jkt) and token_type is
	// returned as "DPoP" instead of "Bearer".
	DPoPProof string `header:"DPoP" doc:"DPoP proof JWT (RFC 9449)"`
	Body      struct {
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
		// CIBA (urn:openid:params:grant-type:ciba) grant fields:
		AuthReqID string `json:"auth_req_id,omitempty" doc:"Backchannel auth_req_id returned from /oauth2/bc-authorize"`
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
		return oautherror.InsufficientScope, err.Error(), http.StatusBadRequest
	}
	// Identity gates can fire at the chokepoint after the per-grant
	// check passed (TOCTOU window). Map to stable error_description
	// strings — the per-grant checks emit the exact same values, so
	// callers see a consistent hint regardless of which code path fired.
	// Using err.Error() here would leak the wrapped chain (which includes
	// the literal expires_at timestamp) and produce a different string
	// shape than the per-grant path.
	if errors.Is(err, domain.ErrIdentityExpired) {
		return oautherror.InvalidGrant, "identity_expired", http.StatusBadRequest
	}
	if errors.Is(err, domain.ErrIdentityNotUsable) {
		return oautherror.InvalidGrant, "identity is suspended or deactivated", http.StatusBadRequest
	}
	if errors.Is(err, domain.ErrCredentialExpired) {
		return oautherror.InvalidGrant, "credential_expired", http.StatusBadRequest
	}
	return oautherror.ServerError, "an unexpected error occurred", http.StatusInternalServerError
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
		Description: "Publicly accessible — tenant is derived from credential material, not headers.\n\n" +
			"**TTL narrowing:** the returned `expires_in` (and the JWT `exp` claim) may be **less** than what the caller requested. " +
			"This happens — silently, RFC 6749 §3.3-style — when the issued token's lifetime would otherwise outlive a bound that " +
			"constrains it. Effective TTL is `min(requested_ttl, service_max_ttl, policy.max_ttl_seconds, time_until(identity.expires_at), time_until(credential.expires_at))`. " +
			"Callers MUST use `expires_in` from the response (not the value they requested) when scheduling refresh. " +
			"Server-side logs name the clamp reason; the chokepoint emits a structured log line with `requested_ttl` and the remaining lifetime that won.\n\n" +
			"**DPoP (RFC 9449):** Clients may attach a `DPoP` header carrying a proof JWT to bind the issued token to a key. " +
			"When the proof validates, the response sets `token_type: \"DPoP\"` (instead of `\"Bearer\"`) and the issued JWT carries " +
			"a `cnf.jkt` claim equal to the proof key's JWK thumbprint. Resource servers retrieve `cnf` via introspection and " +
			"validate the caller's per-request DPoP proof themselves. Proof JTIs are single-use within a 60s freshness window.",
		Tags: []string{"OAuth"},
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
		OperationID: "oauth-bc-authorize",
		Method:      http.MethodPost,
		Path:        "/oauth2/bc-authorize",
		Summary:     "CIBA Backchannel Authorization (OpenID CIBA Core 1.0 §7)",
		Description: "Initiates a backchannel authentication request. Returns an auth_req_id the " +
			"client polls /oauth2/token with grant_type=urn:openid:params:grant-type:ciba until the " +
			"user approves or denies via the deployer's notification channel.",
		Tags: []string{"OAuth"},
	}, a.bcAuthorizeOp)

	advertiseFormContentType(api, "/oauth2/token", "/oauth2/token/introspect", "/oauth2/token/revoke", "/oauth2/bc-authorize")
}

// CIBA approve/deny endpoints — mounted under the admin group so the deployer's
// user-auth gateway sits in front of them. ZeroID has no built-in user
// authentication surface; tenant isolation comes from the X-Account-ID /
// X-Project-ID headers populated by TenantContextMiddleware.
func (a *API) registerBackchannelAdminRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "oauth-bc-approve",
		Method:      http.MethodPost,
		Path:        "/oauth2/bc-authorize/{auth_req_id}/approve",
		Summary:     "Approve a pending CIBA authentication request",
		Description: "Admin-side; tenant-scoped. The deployer's user-auth gateway " +
			"authenticates the end user before forwarding to this endpoint.",
		Tags: []string{"OAuth"},
	}, a.bcApproveOp)

	huma.Register(api, huma.Operation{
		OperationID: "oauth-bc-deny",
		Method:      http.MethodPost,
		Path:        "/oauth2/bc-authorize/{auth_req_id}/deny",
		Summary:     "Deny a pending CIBA authentication request",
		Tags:        []string{"OAuth"},
	}, a.bcDenyOp)
}

// advertiseFormContentType mirrors the JSON request-body schema Huma generated
// for each given path into an additional application/x-www-form-urlencoded
// entry. Generated OpenAPI clients then know these endpoints accept form
// encoding (as RFC 6749/7662/7009 require) in addition to the JSON shape the
// input struct declares.
//
// Safe because oauthFormCompatMiddleware rewrites form bodies to JSON before
// the handler runs, so the JSON-generated schema is the effective schema for
// both content types.
func advertiseFormContentType(api huma.API, paths ...string) {
	oapi := api.OpenAPI()
	if oapi == nil || oapi.Paths == nil {
		return
	}
	for _, p := range paths {
		item, ok := oapi.Paths[p]
		if !ok || item == nil || item.Post == nil || item.Post.RequestBody == nil {
			continue
		}
		content := item.Post.RequestBody.Content
		if content == nil {
			continue
		}
		jsonMT, ok := content["application/json"]
		if !ok || jsonMT == nil {
			continue
		}
		// Shallow-copy the MediaType so the JSON and form entries stay
		// decoupled. Future spec-post-processing (adding an example, a
		// content-type-specific encoding hint) must not cross-contaminate.
		// Nested pointers (Schema, Examples, Encoding) are shared — safe
		// because those structures are not mutated after registration.
		formMT := *jsonMT
		content["application/x-www-form-urlencoded"] = &formMT
	}
}

func (a *API) tokenOp(ctx context.Context, input *TokenInput) (*TokenOutput, error) {
	// DPoP: optional. When a proof is present the issued token is bound to the
	// proof key via cnf.jkt and token_type is returned as "DPoP" (RFC 9449).
	var dpopThumbprint string
	if input.DPoPProof != "" {
		if a.dpopSvc == nil {
			return &TokenOutput{
				Status: http.StatusBadRequest,
				Body:   oauthErrorBody{Error: oautherror.InvalidDPoPProof, ErrorDescription: "DPoP is not enabled on this deployment"},
			}, nil
		}
		// htu must match what the client signed. Prefer the request's effective URL
		// (recorded by RequestURLMiddleware) so reverse-proxied deployments work
		// transparently; fall back to the configured issuer URL only when the
		// middleware was not installed (defensive, should not happen in production).
		htu := internalMiddleware.EffectiveRequestURL(ctx)
		if htu == "" {
			htu = a.issuer + "/oauth2/token"
		}
		tp, dpopErr := a.dpopSvc.ValidateProof(ctx, http.MethodPost, htu, input.DPoPProof)
		if dpopErr != nil {
			if errors.Is(dpopErr, service.ErrDPoPStorageFailure) {
				log.Error().Err(dpopErr).Msg("DPoP JTI store unavailable")
				return &TokenOutput{
					Status: http.StatusInternalServerError,
					Body:   oauthErrorBody{Error: oautherror.ServerError, ErrorDescription: "failed to validate DPoP proof"},
				}, nil
			}
			return &TokenOutput{
				Status: http.StatusBadRequest,
				Body:   oauthErrorBody{Error: oautherror.InvalidDPoPProof, ErrorDescription: dpopErr.Error()},
			}, nil
		}
		dpopThumbprint = tp
	}

	accessToken, err := a.oauthSvc.Token(ctx, service.TokenRequest{
		GrantType:         input.Body.GrantType,
		ClientID:          input.Body.ClientID,
		ClientSecret:      input.Body.ClientSecret,
		Scope:             input.Body.Scope,
		AccountID:         input.Body.AccountID,
		ProjectID:         input.Body.ProjectID,
		Subject:           input.Body.Subject,
		APIKey:            input.Body.APIKey,
		SubjectToken:      input.Body.SubjectToken,
		SubjectTokenType:  input.Body.SubjectTokenType,
		ActorToken:        input.Body.ActorToken,
		UserID:            input.Body.UserID,
		UserEmail:         input.Body.UserEmail,
		UserName:          input.Body.UserName,
		ApplicationID:     input.Body.ApplicationID,
		AdditionalClaims:  input.Body.AdditionalClaims,
		Code:              input.Body.Code,
		CodeVerifier:      input.Body.CodeVerifier,
		RedirectURI:       input.Body.RedirectURI,
		RefreshTokenStr:   input.Body.RefreshToken,
		AuthReqID:         input.Body.AuthReqID,
		DPoPKeyThumbprint: dpopThumbprint,
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

// ── CIBA handlers ────────────────────────────────────────────────────────────

// BcAuthorizeInput is the OpenID CIBA Core 1.0 §7.1 request shape.
// account_id / project_id are ZeroID-specific because the public endpoint has
// no other way to convey tenant — there's no X-Account-ID header on the
// public group, and we don't want to lean on client_id → tenant lookup
// (clients in ZeroID are global to all tenants).
type BcAuthorizeInput struct {
	Body struct {
		ClientID                string `json:"client_id" required:"true" doc:"OAuth client initiating the backchannel request"`
		AccountID               string `json:"account_id" required:"true" doc:"Tenant account ID"`
		ProjectID               string `json:"project_id" required:"true" doc:"Tenant project ID"`
		LoginHint               string `json:"login_hint,omitempty" doc:"User identifier (email, phone, user_id). Required IF group_hint is not supplied."`
		GroupHint               string `json:"group_hint,omitempty" doc:"CIBA extension — opaque deployer-namespaced identifier for role/group-targeted approval (e.g. 'highflame:role:finance_lead'). Required IF login_hint is not supplied. Max 255 codepoints (multi-byte UTF-8 accepted)."`
		Scope                   string `json:"scope,omitempty" doc:"Requested scopes (space-delimited)"`
		BindingMessage          string `json:"binding_message,omitempty" doc:"Human-readable context shown to the user during approval"`
		RequestedExpiry         int    `json:"requested_expiry,omitempty" doc:"Auth-request TTL in seconds; bounded by server default"`
		ClientNotificationToken string `json:"client_notification_token,omitempty" doc:"Bearer the server echoes in the ping callback (required for ping mode)"`
		// AuthorizationDetails is the RFC 9396 Rich Authorization Requests
		// payload — a JSON array of typed objects describing what is being
		// authorized at a finer granularity than scope. ZeroID validates
		// the outer shape (array of objects, each with a non-empty string
		// `type` field) and runs any registered per-type validators; the
		// raw bytes are persisted on the auth request row and delivered
		// to the BackchannelNotifier hook for typed approval-prompt
		// rendering. Empty / omitted keeps the legacy CIBA flow unchanged.
		AuthorizationDetails json.RawMessage `json:"authorization_details,omitempty" doc:"RFC 9396 Rich Authorization Requests payload (JSON array of typed objects)"`
	}
}

// BcAuthorizeOutput mirrors the success response in CIBA Core §7.3.
type BcAuthorizeOutput struct {
	Status int
	Body   any // service.CreateAuthRequestOutput on success; oauthErrorBody on error
}

func (a *API) bcAuthorizeOp(ctx context.Context, input *BcAuthorizeInput) (*BcAuthorizeOutput, error) {
	if a.backchannelSvc == nil {
		// Service not wired — same shape as the dispatch-side error so
		// clients see a consistent error_code regardless of where the
		// gate trips.
		return &BcAuthorizeOutput{
			Status: http.StatusBadRequest,
			Body:   oauthErrorBody{Error: oautherror.UnsupportedGrantType, ErrorDescription: "CIBA is not enabled on this deployment"},
		}, nil
	}
	out, err := a.backchannelSvc.CreateAuthRequest(ctx, service.CreateAuthRequestInput{
		ClientID:                input.Body.ClientID,
		AccountID:               input.Body.AccountID,
		ProjectID:               input.Body.ProjectID,
		LoginHint:               input.Body.LoginHint,
		GroupHint:               input.Body.GroupHint,
		Scope:                   input.Body.Scope,
		BindingMessage:          input.Body.BindingMessage,
		RequestedExpiry:         input.Body.RequestedExpiry,
		ClientNotificationToken: input.Body.ClientNotificationToken,
		AuthorizationDetailsRaw: []byte(input.Body.AuthorizationDetails),
	})
	if err != nil {
		log.Error().Err(err).Str("client_id", input.Body.ClientID).Msg("bc-authorize failed")
		code, desc, status := extractOAuthError(err)
		return &BcAuthorizeOutput{Status: status, Body: oauthErrorBody{Error: code, ErrorDescription: desc}}, nil
	}
	return &BcAuthorizeOutput{Status: http.StatusOK, Body: out}, nil
}

// BcApproveInput resolves a pending request positively. auth_req_id is the
// URL path parameter; tenant is read from request headers via TenantContext.
type BcApproveInput struct {
	AuthReqID string `path:"auth_req_id" required:"true"`
	Body      struct {
		SubjectID    string `json:"subject_id" required:"true" doc:"Approved end-user identifier (becomes JWT sub)"`
		SubjectEmail string `json:"subject_email,omitempty" doc:"Approved user email (optional)"`
		SubjectName  string `json:"subject_name,omitempty" doc:"Approved user display name (optional)"`
	}
}

type BcApproveOutput struct {
	Status int
	Body   struct {
		AuthReqID string `json:"auth_req_id"`
		Status    string `json:"status"`
	}
}

func (a *API) bcApproveOp(ctx context.Context, input *BcApproveInput) (*BcApproveOutput, error) {
	if a.backchannelSvc == nil {
		return nil, huma.Error400BadRequest("CIBA is not enabled on this deployment")
	}
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		// Missing X-Account-ID / X-Project-ID is a request-formedness
		// failure (admin endpoints have no built-in auth — the deployer's
		// edge service is responsible for setting routing headers after
		// its own auth check). 400, not 401: there are no credentials in
		// play at this layer.
		return nil, huma.Error400BadRequest("missing X-Account-ID or X-Project-ID header")
	}
	if err := a.backchannelSvc.Approve(ctx, service.ApproveInput{
		AuthReqID:    input.AuthReqID,
		AccountID:    tenant.AccountID,
		ProjectID:    tenant.ProjectID,
		SubjectID:    input.Body.SubjectID,
		SubjectEmail: input.Body.SubjectEmail,
		SubjectName:  input.Body.SubjectName,
	}); err != nil {
		return nil, mapBackchannelAdminError(err)
	}
	out := &BcApproveOutput{Status: http.StatusOK}
	out.Body.AuthReqID = input.AuthReqID
	out.Body.Status = "approved"
	return out, nil
}

// BcDenyInput resolves a pending request negatively.
type BcDenyInput struct {
	AuthReqID string `path:"auth_req_id" required:"true"`
}

type BcDenyOutput struct {
	Status int
	Body   struct {
		AuthReqID string `json:"auth_req_id"`
		Status    string `json:"status"`
	}
}

func (a *API) bcDenyOp(ctx context.Context, input *BcDenyInput) (*BcDenyOutput, error) {
	if a.backchannelSvc == nil {
		return nil, huma.Error400BadRequest("CIBA is not enabled on this deployment")
	}
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		// See bcApproveOp comment — same 400-not-401 rationale.
		return nil, huma.Error400BadRequest("missing X-Account-ID or X-Project-ID header")
	}
	if err := a.backchannelSvc.Deny(ctx, service.DenyInput{
		AuthReqID: input.AuthReqID,
		AccountID: tenant.AccountID,
		ProjectID: tenant.ProjectID,
	}); err != nil {
		return nil, mapBackchannelAdminError(err)
	}
	out := &BcDenyOutput{Status: http.StatusOK}
	out.Body.AuthReqID = input.AuthReqID
	out.Body.Status = "denied"
	return out, nil
}

// mapBackchannelAdminError converts a service-layer OAuthError into a Huma
// admin error. The admin endpoints are not OAuth token endpoints, so the
// RFC 6749 §5.2 error_code/error_description envelope would be misleading
// here; we use plain HTTP semantics instead.
//
// The backchannel service produces only 400 and 500 OAuthErrors — there's
// no auth surface inside the service (admin auth happens at the handler /
// edge layer, see bcApproveOp / bcDenyOp). 401 would be returned only if
// the service started producing invalid_client errors directly, which it
// doesn't today; if that ever changes, add a case here AND consider
// whether the failure is really an OAuth client-auth failure (RFC 9728
// §5.1 breadcrumb applies) or just a misuse of OAuthError shape (it
// doesn't apply).
func mapBackchannelAdminError(err error) error {
	var oauthErr *service.OAuthError
	if errors.As(err, &oauthErr) {
		switch oauthErr.HTTPStatus {
		case http.StatusBadRequest:
			return huma.Error400BadRequest(oauthErr.Description)
		case http.StatusInternalServerError:
			return huma.Error500InternalServerError(oauthErr.Description)
		}
	}
	return huma.Error500InternalServerError("backchannel admin request failed")
}
