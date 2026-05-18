package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/service"
)

// allowedDCRGrantTypes are the only grant types permitted for dynamically
// registered clients. authorization_code is intentionally excluded — this is
// a machine-to-machine server and DCR-registered clients can't run an
// interactive consent flow. token-exchange (RFC 8693) is intentionally excluded
// too — DCR-registered clients have no IdentityID binding and so cannot
// legitimately act as a delegation actor; allowing the grant type at
// registration time creates a sharp edge for no benefit. Add it back when
// DCR-clients-as-actors becomes a real use case with explicit identity binding.
var allowedDCRGrantTypes = map[string]bool{
	"client_credentials":                          true,
	"urn:ietf:params:oauth:grant-type:jwt-bearer": true,
}

// dcrClientRegisterScope is the scope an initial access token must carry to
// be allowed to call POST /oauth2/register.
const dcrClientRegisterScope = "client:register"

// ── DCR types ────────────────────────────────────────────────────────────────

// DCRRegisterInput is the RFC 7591 §3.1 registration request, with the
// initial access token presented as a Bearer header.
type DCRRegisterInput struct {
	Authorization string `header:"Authorization" required:"true" doc:"Initial access token: Bearer <jwt>"`
	Body          struct {
		ClientName              string   `json:"client_name" required:"true" doc:"Human-readable client name"`
		GrantTypes              []string `json:"grant_types,omitempty" doc:"OAuth grant types (defaults to client_credentials)"`
		Scope                   string   `json:"scope,omitempty" doc:"Space-separated scope list"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty" doc:"client_secret_post or client_secret_basic"`
		SoftwareID              string   `json:"software_id,omitempty" doc:"Software identifier (RFC 7591)"`
		SoftwareVersion         string   `json:"software_version,omitempty" doc:"Software version (RFC 7591)"`
		Contacts                []string `json:"contacts,omitempty" doc:"Operator contact emails"`
		// RedirectURIs is accepted, persisted, and echoed back on GET/PUT
		// for RFC 7591/7592 metadata-roundtrip fidelity, but it is not
		// consulted at /oauth2/token time — DCR clients have no
		// authorization_code grant in the allow-list and therefore no
		// redirect-URI step in any code path. Stored, not used.
		RedirectURIs []string `json:"redirect_uris,omitempty" doc:"Stored on the client record but unused at token time (no interactive flows are allowed for DCR clients)"`
	}
}

// DCROutput is the polymorphic response body. RFC 7591/7592 success bodies are
// dynamic-shape; error bodies are oauthErrorBody.
type DCROutput struct {
	Status int
	Body   any
}

// DCRGetInput / DCRUpdateInput / DCRDeleteInput share the same auth shape:
// the registration_access_token in the Authorization header, and client_id in
// the path.
type DCRGetInput struct {
	Authorization string `header:"Authorization" required:"true" doc:"Bearer registration_access_token"`
	ClientID      string `path:"client_id" required:"true" doc:"OAuth client_id from registration"`
}

type DCRUpdateInput struct {
	Authorization string `header:"Authorization" required:"true" doc:"Bearer registration_access_token"`
	ClientID      string `path:"client_id" required:"true" doc:"OAuth client_id from registration"`
	Body          struct {
		ClientName              string   `json:"client_name" required:"true"`
		GrantTypes              []string `json:"grant_types,omitempty"`
		Scope                   string   `json:"scope,omitempty"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
		SoftwareID              string   `json:"software_id,omitempty"`
		SoftwareVersion         string   `json:"software_version,omitempty"`
		Contacts                []string `json:"contacts,omitempty"`
		RedirectURIs            []string `json:"redirect_uris,omitempty"`
	}
}

type DCRDeleteInput struct {
	Authorization string `header:"Authorization" required:"true" doc:"Bearer registration_access_token"`
	ClientID      string `path:"client_id" required:"true" doc:"OAuth client_id from registration"`
}

// ── DCR routes ───────────────────────────────────────────────────────────────

// registerDynamicRegistrationRoutes mounts the RFC 7591/7592 endpoints on the
// public group. Authentication is intrinsic to each request:
//   - POST                       — initial access token JWT with client:register scope.
//   - GET / PUT / DELETE         — registration_access_token issued at registration.
func (a *API) registerDynamicRegistrationRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "oauth-register",
		Method:      http.MethodPost,
		Path:        "/oauth2/register",
		Summary:     "Dynamic Client Registration (RFC 7591)",
		Description: "Registers a new OAuth2 client. Requires an initial access token JWT " +
			"with the `client:register` scope in its scopes claim — issued out-of-band " +
			"to authorised registrants. Returns the new client_id, client_secret, and a " +
			"registration_access_token that authenticates subsequent RFC 7592 management calls.",
		Tags: []string{"OAuth"},
	}, a.dcrRegisterOp)

	huma.Register(api, huma.Operation{
		OperationID: "oauth-registration-get",
		Method:      http.MethodGet,
		Path:        "/oauth2/register/{client_id}",
		Summary:     "Read Client Registration (RFC 7592)",
		Tags:        []string{"OAuth"},
	}, a.dcrGetOp)

	huma.Register(api, huma.Operation{
		OperationID: "oauth-registration-update",
		Method:      http.MethodPut,
		Path:        "/oauth2/register/{client_id}",
		Summary:     "Update Client Registration (RFC 7592)",
		Description: "Full replacement, not partial update (RFC 7592 §3). Omitted fields revert to RFC 7591 defaults.",
		Tags:        []string{"OAuth"},
	}, a.dcrUpdateOp)

	huma.Register(api, huma.Operation{
		OperationID: "oauth-registration-delete",
		Method:      http.MethodDelete,
		Path:        "/oauth2/register/{client_id}",
		Summary:     "Delete Client Registration (RFC 7592)",
		Tags:        []string{"OAuth"},
	}, a.dcrDeleteOp)
}

// ── DCR ops ──────────────────────────────────────────────────────────────────

func (a *API) dcrRegisterOp(ctx context.Context, input *DCRRegisterInput) (*DCROutput, error) {
	iatClaims, err := a.validateInitialAccessToken(input.Authorization)
	if err != nil {
		return dcrErr(err), nil
	}

	v, err := validateDCRClientMetadata(input.Body.ClientName, input.Body.Scope, input.Body.TokenEndpointAuthMethod, input.Body.GrantTypes)
	if err != nil {
		return dcrErr(err), nil
	}

	client, plainSecret, plainRegToken, regErr := a.oauthClientSvc.DynamicRegisterClient(ctx, service.DynamicRegisterClientRequest{
		Name:                    input.Body.ClientName,
		GrantTypes:              v.GrantTypes,
		Scopes:                  v.Scopes,
		TokenEndpointAuthMethod: v.AuthMethod,
		SoftwareID:              input.Body.SoftwareID,
		SoftwareVersion:         input.Body.SoftwareVersion,
		Contacts:                input.Body.Contacts,
		RedirectURIs:            input.Body.RedirectURIs,
	})
	if regErr != nil {
		if errors.Is(regErr, service.ErrOAuthClientAlreadyExists) {
			return dcrErr(&dcrError{status: http.StatusConflict, code: "invalid_client_metadata", desc: "client already exists"}), nil
		}
		log.Error().Err(regErr).Msg("dynamic client registration failed")
		return dcrErr(&dcrError{status: http.StatusInternalServerError, code: "server_error", desc: "failed to register client"}), nil
	}

	// Audit log: who minted what. registered_by_* claims are derived from the
	// initial access token; clients themselves remain global per zeroid's
	// design but the registrant's tenant context is preserved here for ops.
	log.Info().
		Str("client_id", client.ClientID).
		Str("registered_by_sub", iatClaims.Subject).
		Str("registered_by_account_id", iatClaims.AccountID).
		Str("registered_by_project_id", iatClaims.ProjectID).
		Msg("DCR: dynamic client registered")

	// Register response = the standard GET/PUT shape (dcrClientResponse) plus
	// the two values that are shown exactly once and never re-revealed.
	body := a.dcrClientResponse(client)
	body["client_secret"] = plainSecret
	body["registration_access_token"] = plainRegToken
	return &DCROutput{Status: http.StatusCreated, Body: body}, nil
}

func (a *API) dcrGetOp(ctx context.Context, input *DCRGetInput) (*DCROutput, error) {
	cl, err := a.authorizeDCRManagement(ctx, input.Authorization, input.ClientID)
	if err != nil {
		return dcrErr(err), nil
	}
	return &DCROutput{Status: http.StatusOK, Body: a.dcrClientResponse(cl)}, nil
}

func (a *API) dcrUpdateOp(ctx context.Context, input *DCRUpdateInput) (*DCROutput, error) {
	if _, err := a.authorizeDCRManagement(ctx, input.Authorization, input.ClientID); err != nil {
		return dcrErr(err), nil
	}

	v, err := validateDCRClientMetadata(input.Body.ClientName, input.Body.Scope, input.Body.TokenEndpointAuthMethod, input.Body.GrantTypes)
	if err != nil {
		return dcrErr(err), nil
	}

	updated, updateErr := a.oauthClientSvc.UpdateDynamicClient(ctx, input.ClientID, service.DynamicRegisterClientRequest{
		Name:                    input.Body.ClientName,
		GrantTypes:              v.GrantTypes,
		Scopes:                  v.Scopes,
		TokenEndpointAuthMethod: v.AuthMethod,
		SoftwareID:              input.Body.SoftwareID,
		SoftwareVersion:         input.Body.SoftwareVersion,
		Contacts:                input.Body.Contacts,
		RedirectURIs:            input.Body.RedirectURIs,
	})
	if updateErr != nil {
		// Race window between authorizeDCRManagement and Update: client may
		// have been deleted in between. Map ErrOAuthClientNotFound to the
		// same 401 the auth path uses; other errors are infra failures.
		if errors.Is(updateErr, service.ErrOAuthClientNotFound) {
			return dcrErr(&dcrError{status: http.StatusUnauthorized, code: "invalid_token", desc: "client no longer exists"}), nil
		}
		log.Error().Err(updateErr).Str("client_id", input.ClientID).Msg("dynamic client update failed")
		return dcrErr(&dcrError{status: http.StatusInternalServerError, code: "server_error", desc: "failed to update client registration"}), nil
	}
	return &DCROutput{Status: http.StatusOK, Body: a.dcrClientResponse(updated)}, nil
}

func (a *API) dcrDeleteOp(ctx context.Context, input *DCRDeleteInput) (*DCROutput, error) {
	if _, err := a.authorizeDCRManagement(ctx, input.Authorization, input.ClientID); err != nil {
		return dcrErr(err), nil
	}
	if err := a.oauthClientSvc.DeleteDynamicClient(ctx, input.ClientID); err != nil {
		log.Error().Err(err).Str("client_id", input.ClientID).Msg("dynamic client delete failed")
		return dcrErr(&dcrError{status: http.StatusInternalServerError, code: "server_error", desc: "failed to delete client registration"}), nil
	}
	return &DCROutput{Status: http.StatusNoContent, Body: nil}, nil
}

// ── DCR helpers ──────────────────────────────────────────────────────────────

// dcrValidatedFields collects the post-validation client metadata shared by
// register + update.
type dcrValidatedFields struct {
	GrantTypes []string
	Scopes     []string
	AuthMethod string
}

// validateDCRClientMetadata applies RFC 7591/7592 input rules: client_name
// required, grant_types subset of allowedDCRGrantTypes, token_endpoint_auth_method
// constrained to client_secret_post / client_secret_basic. Defaults are filled
// in. Returns the normalised fields or a *dcrError ready for dcrErr().
func validateDCRClientMetadata(clientName, scopeStr, authMethodIn string, grantTypesIn []string) (*dcrValidatedFields, *dcrError) {
	if clientName == "" {
		return nil, &dcrError{status: http.StatusBadRequest, code: "invalid_client_metadata", desc: "client_name is required"}
	}
	grantTypes := grantTypesIn
	if len(grantTypes) == 0 {
		grantTypes = []string{"client_credentials"}
	}
	for _, gt := range grantTypes {
		if !allowedDCRGrantTypes[gt] {
			return nil, &dcrError{status: http.StatusBadRequest, code: "invalid_client_metadata", desc: "unsupported grant_type: " + gt}
		}
	}
	authMethod := authMethodIn
	switch authMethod {
	case "":
		// RFC 7591 §2 default. Applying it here makes the validator's
		// "normalised fields" contract honest — the response body's
		// token_endpoint_auth_method will report the effective value
		// even when the caller omitted the field.
		authMethod = "client_secret_basic"
	case "client_secret_post", "client_secret_basic":
		// accepted
	case "none":
		return nil, &dcrError{status: http.StatusBadRequest, code: "invalid_client_metadata", desc: "token_endpoint_auth_method 'none' is not supported; this server requires client authentication"}
	default:
		return nil, &dcrError{status: http.StatusBadRequest, code: "invalid_client_metadata", desc: "unsupported token_endpoint_auth_method: " + authMethod}
	}
	var scopes []string
	if scopeStr != "" {
		scopes = strings.Fields(scopeStr)
	} else {
		scopes = []string{}
	}
	return &dcrValidatedFields{GrantTypes: grantTypes, Scopes: scopes, AuthMethod: authMethod}, nil
}

// dcrError is the structured error a DCR op returns to the dispatch layer.
// It's the only error type the helpers below ever produce; the typed
// parameter in `dcrErr` (rather than the `error` interface) makes that
// invariant compile-time-enforced and avoids a dead "unexpected error"
// fallback branch.
type dcrError struct {
	status int
	code   string
	desc   string
}

func (e *dcrError) Error() string { return e.code + ": " + e.desc }

func dcrErr(de *dcrError) *DCROutput {
	return &DCROutput{Status: de.status, Body: oauthErrorBody{Error: de.code, ErrorDescription: de.desc}}
}

// initialAccessTokenClaims captures the tenant-relevant claims of a successfully
// validated initial access token. Used for audit logging only — DCR-registered
// OAuth clients are global (no tenant column) by design.
type initialAccessTokenClaims struct {
	Subject   string
	AccountID string
	ProjectID string
}

// validateInitialAccessToken parses the Authorization header as `Bearer <jwt>`,
// verifies against the server's JWKS, and requires:
//   - iss equal to the configured issuer (defense against tokens from another AS),
//   - aud containing the configured issuer (defense against tokens minted for a
//     different protected resource being replayed at /oauth2/register; per
//     RFC 9068 §3, ZeroID-issued access tokens default to aud=[issuer]),
//   - the `client:register` scope present in the scopes claim.
//
// Returns the extracted tenant claims on success or a *dcrError on failure.
func (a *API) validateInitialAccessToken(authHeader string) (*initialAccessTokenClaims, *dcrError) {
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, &dcrError{status: http.StatusUnauthorized, code: "invalid_token", desc: "Authorization header with Bearer initial access token is required"}
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	parsed, err := jwt.Parse([]byte(tokenStr),
		jwt.WithKeySet(a.jwksSvc.KeySet()),
		jwt.WithValidate(true),
		jwt.WithIssuer(a.issuer),
		jwt.WithAudience(a.issuer),
	)
	if err != nil {
		log.Info().Err(err).Msg("DCR: initial access token rejected")
		return nil, &dcrError{status: http.StatusUnauthorized, code: "invalid_token", desc: "initial access token is invalid or expired"}
	}

	// The scopes claim may decode as []string (when jwx preserves the issuance
	// shape) or []any (when JSON-parsed without type hints). Mirror the
	// AgentAuthMiddleware pattern: try []string first, then []any. Without
	// this, ZeroID-issued tokens (which set scopes as []string at issuance)
	// would never appear to have the client:register scope.
	hasRegisterScope := false
	if scopes, err := jwt.Get[[]string](parsed, "scopes"); err == nil {
		for _, sc := range scopes {
			if sc == dcrClientRegisterScope {
				hasRegisterScope = true
				break
			}
		}
	} else if scopes, err := jwt.Get[[]any](parsed, "scopes"); err == nil {
		for _, sc := range scopes {
			if str, ok := sc.(string); ok && str == dcrClientRegisterScope {
				hasRegisterScope = true
				break
			}
		}
	}
	if !hasRegisterScope {
		log.Info().Msg("DCR: initial access token rejected — insufficient scope")
		return nil, &dcrError{status: http.StatusForbidden, code: "insufficient_scope", desc: "initial access token must have '" + dcrClientRegisterScope + "' scope"}
	}

	claims := &initialAccessTokenClaims{}
	claims.Subject, _ = parsed.Subject()
	claims.AccountID, _ = jwt.Get[string](parsed, "account_id")
	claims.ProjectID, _ = jwt.Get[string](parsed, "project_id")
	// Audit trail integrity: an IAT whose account_id / project_id claims are
	// stripped would still pass the iss/aud/scope checks but produce an
	// audit log with empty registered_by_* fields, muddying who registered
	// what. The IAT issuer (the platform) controls these claims, so the
	// requirement is a sanity check against mis-issued tokens, not a
	// trust-boundary check.
	if claims.AccountID == "" || claims.ProjectID == "" {
		log.Info().
			Str("registered_by_sub", claims.Subject).
			Msg("DCR: initial access token rejected — missing tenant claims")
		return nil, &dcrError{status: http.StatusForbidden, code: "invalid_token", desc: "initial access token must carry account_id and project_id claims"}
	}
	return claims, nil
}

// authorizeDCRManagement verifies the registration_access_token in the
// Authorization header against the stored bcrypt hash for the path's client_id.
func (a *API) authorizeDCRManagement(ctx context.Context, authHeader, clientID string) (*domain.OAuthClient, *dcrError) {
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, &dcrError{status: http.StatusUnauthorized, code: "invalid_token", desc: "Authorization header with Bearer registration_access_token is required"}
	}
	regToken := strings.TrimPrefix(authHeader, "Bearer ")

	client, err := a.oauthClientSvc.VerifyRegistrationToken(ctx, clientID, regToken)
	if err != nil {
		// 401 for genuine not-found / bad token; 500 for DB / infra failures so an
		// outage isn't masked as an auth rejection.
		if errors.Is(err, service.ErrOAuthClientNotFound) {
			return nil, &dcrError{status: http.StatusUnauthorized, code: "invalid_token", desc: "invalid or unknown registration_access_token"}
		}
		log.Error().Err(err).Str("client_id", clientID).Msg("DCR: registration-token verification failed")
		return nil, &dcrError{status: http.StatusInternalServerError, code: "server_error", desc: "failed to verify registration token"}
	}
	return client, nil
}

// dcrClientResponse returns the RFC 7591 §3.2.1 / RFC 7592 §3 representation of a
// registered client. Used for GET/PUT responses (secrets are not re-revealed
// after the initial registration).
func (a *API) dcrClientResponse(cl *domain.OAuthClient) map[string]any {
	return map[string]any{
		"client_id":                  cl.ClientID,
		"client_id_issued_at":        cl.CreatedAt.Unix(),
		"client_secret_expires_at":   0,
		"client_name":                cl.Name,
		"grant_types":                cl.GrantTypes,
		"scope":                      strings.Join(cl.Scopes, " "),
		"token_endpoint_auth_method": cl.TokenEndpointAuthMethod,
		"registration_client_uri":    a.baseURL + "/oauth2/register/" + cl.ClientID,
	}
}
