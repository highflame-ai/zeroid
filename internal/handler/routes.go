// Package handler provides HTTP handlers for the ZeroID service.
// Huma v2 is used for all standard request-response endpoints, providing automatic
// OpenAPI spec generation, RFC 9457 error responses, and declarative input validation.
// SSE streaming endpoints remain on raw chi.
package handler

import (
	"io"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	gojson "github.com/goccy/go-json"
	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/internal/service"
	"github.com/highflame-ai/zeroid/internal/signing"
)

// API holds all service dependencies and exposes Huma-compatible handler methods.
type API struct {
	identitySvc         *service.IdentityService
	credSvc             *service.CredentialService
	credentialPolicySvc *service.CredentialPolicyService
	attestationSvc      *service.AttestationService
	proofSvc            *service.ProofService
	oauthSvc            *service.OAuthService
	oauthClientSvc      *service.OAuthClientService
	signalSvc           *service.SignalService
	apiKeySvc           *service.APIKeyService
	agentSvc            *service.AgentService
	jwksSvc             *signing.JWKSService
	db                  *bun.DB
	issuer              string
	baseURL             string
	startTime           time.Time
}

// NewAPI creates a new API with all service dependencies.
func NewAPI(
	identitySvc *service.IdentityService,
	credSvc *service.CredentialService,
	credentialPolicySvc *service.CredentialPolicyService,
	attestationSvc *service.AttestationService,
	proofSvc *service.ProofService,
	oauthSvc *service.OAuthService,
	oauthClientSvc *service.OAuthClientService,
	signalSvc *service.SignalService,
	apiKeySvc *service.APIKeyService,
	agentSvc *service.AgentService,
	jwksSvc *signing.JWKSService,
	db *bun.DB,
	issuer, baseURL string,
) *API {
	return &API{
		identitySvc:         identitySvc,
		credSvc:             credSvc,
		credentialPolicySvc: credentialPolicySvc,
		attestationSvc:      attestationSvc,
		proofSvc:            proofSvc,
		oauthSvc:            oauthSvc,
		oauthClientSvc:      oauthClientSvc,
		signalSvc:           signalSvc,
		apiKeySvc:           apiKeySvc,
		agentSvc:            agentSvc,
		jwksSvc:             jwksSvc,
		db:                  db,
		issuer:              issuer,
		baseURL:             baseURL,
		startTime:           time.Now(),
	}
}

// NewHumaAPI creates a Huma API on the given chi router with goccy/go-json codec.
func NewHumaAPI(router chi.Router) huma.API {
	config := huma.DefaultConfig("ZeroID", "1.0.0")
	config.Info.Description = "Non-Human Identity (NHI) management — agent authentication, credential lifecycle, and delegation."

	// Override JSON format with goccy/go-json for 2-3x faster serialization.
	config.Formats["application/json"] = huma.Format{
		Marshal: func(w io.Writer, v any) error {
			return gojson.NewEncoder(w).Encode(v)
		},
		Unmarshal: func(data []byte, v any) error {
			return gojson.Unmarshal(data, v)
		},
	}

	return humachi.New(router, config)
}

// RegisterPublic registers endpoints that require no authentication:
// health, well-known, OAuth2 endpoints (token, revoke), and forward-auth verify.
func (a *API) RegisterPublic(api huma.API, router chi.Router) {
	a.registerHealthRoutes(api)
	a.registerWellKnownRoutes(api)
	a.registerOAuthRoutes(api)
	a.registerAuthVerifyRoute(router)
}

// RegisterAdmin registers admin/management endpoints:
// identities, credentials, policies, attestation, signals, oauth clients, proof verify.
// These run on the admin port which is protected at the network layer.
func (a *API) RegisterAdmin(api huma.API, router chi.Router) {
	a.registerIdentityRoutes(api)
	a.registerCredentialPolicyRoutes(api)
	a.registerCredentialRoutes(api)
	a.registerAttestationRoutes(api)
	a.registerOAuthClientRoutes(api)
	a.registerAPIKeyRoutes(api)
	a.registerAgentRoutes(api)
	a.registerSignalRoutes(api, router)
	a.registerProofVerifyRoute(api)
}

// RegisterAgentAuth registers endpoints requiring agent-auth middleware (proof generation).
// These run on the admin port behind an additional agent JWT verification layer.
func (a *API) RegisterAgentAuth(api huma.API) {
	a.registerProofGenerateRoute(api)
}
