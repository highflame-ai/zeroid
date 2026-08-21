// Package handler provides HTTP handlers for the ZeroID service.
// Huma v2 is used for all standard request-response endpoints, providing automatic
// OpenAPI spec generation, RFC 9457 error responses, and declarative input validation.
// SSE streaming endpoints remain on raw chi.
package handler

import (
	"context"
	"io"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	gojson "github.com/goccy/go-json"
	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/attestation"
	"github.com/highflame-ai/zeroid/internal/service"
	"github.com/highflame-ai/zeroid/internal/signing"
	"github.com/highflame-ai/zeroid/pkg/dpop"
)

// API holds all service dependencies and exposes Huma-compatible handler methods.
type API struct {
	identitySvc          *service.IdentityService
	credSvc              *service.CredentialService
	credentialPolicySvc  *service.CredentialPolicyService
	attestationSvc       *service.AttestationService
	attestationPolicySvc *attestation.PolicyService
	proofSvc             *service.ProofService
	oauthSvc             *service.OAuthService
	oauthClientSvc       *service.OAuthClientService
	signalSvc            *service.SignalService
	apiKeySvc            *service.APIKeyService
	agentSvc             *service.AgentService
	auditSvc             *service.AuditService
	backchannelSvc       *service.BackchannelService
	dpopVerifier         *dpop.Verifier
	delegationSvc        *service.DelegationService
	jwksSvc              *signing.JWKSService
	signingCredSvc       *service.SigningCredentialService
	db                   *bun.DB
	issuer               string
	startTime            time.Time

	// cimdEnabled advertises CIMD support in the OAuth 2.0 Authorization Server
	// Metadata document (client_id_metadata_document_supported). Set via
	// SetCIMDEnabled after construction; defaults false so a build that doesn't
	// wire CIMD doesn't advertise it.
	cimdEnabled bool

	// cimdPublishersVetted reports whether cimd.allowed_domains names at least
	// one host, i.e. whether a deployer decided which hosts may publish a
	// metadata document. It is the gate that lets a CIMD client be treated as
	// a redirect destination — see failAuthorize and redirectToInteractiveLogin,
	// which refuse a self-asserted client only while this is false. Set via
	// SetCIMDPublishersVetted from the EFFECTIVE allow-list, not the raw config
	// slice: NewCIMDService lower-cases and drops blank entries, so
	// allowed_domains: [""] has length 1 and vets nothing.
	cimdPublishersVetted bool

	// authorizationCodeAvailable reports whether /oauth2/authorize can
	// actually serve a request — i.e. whether the deployer registered any
	// PrincipalResolver. A PREDICATE, not a snapshot: resolvers may be
	// registered after NewServer and before Start, so a bool captured at
	// construction time would be wrong. Nil means "assume available"
	// (embedders that never call the setter keep the old behaviour).
	authorizationCodeAvailable func() bool

	// interactiveLoginURL returns where to send a user agent when a resolver
	// reports ErrPrincipalInteractionRequired. Nil means the deployment has no
	// login surface, in which case that sentinel degrades to access_denied — a
	// resolver cannot conjure a surface that does not exist.
	//
	// A func rather than a string so the target can vary per request (tenant,
	// client, locale) without the resolver having to construct redirects itself.
	interactiveLoginURL func(*service.AuthorizeRequest) string

	// resolvePrincipal walks the PrincipalResolver chain registered on
	// the top-level Server. Wired unconditionally by Server.NewServer via
	// SetPrincipalResolverFunc, which passes a BOUND METHOD — so this is
	// never nil, even with an empty registry. An empty chain surfaces as
	// ErrNoResolversRegistered from the call, which the /oauth2/authorize
	// handler maps to 503.
	//
	// It therefore cannot be used to test whether the deployment has any
	// resolvers; that is what authorizationCodeAvailable is for.
	resolvePrincipal PrincipalResolverFunc
}

// PrincipalResolverFunc is the chain-walker function the /oauth2/authorize
// handler calls to resolve the caller's tenant + user context. Returns
// the resolved principal, the name of the resolver that produced it
// (for log attribution), and any error.
//
// The function lives here (handler package) rather than in service or
// the top-level zeroid package so handler can hold it as a field without
// pulling in the resolver-registry mutex. Server constructs an instance
// bound to its own registry and hands it to API at construction time.
type PrincipalResolverFunc func(ctx context.Context, req *service.AuthorizeRequest) (*service.Principal, string, error)

// NewAPI creates a new API with all service dependencies.
func NewAPI(
	identitySvc *service.IdentityService,
	credSvc *service.CredentialService,
	credentialPolicySvc *service.CredentialPolicyService,
	attestationSvc *service.AttestationService,
	attestationPolicySvc *attestation.PolicyService,
	proofSvc *service.ProofService,
	oauthSvc *service.OAuthService,
	oauthClientSvc *service.OAuthClientService,
	signalSvc *service.SignalService,
	apiKeySvc *service.APIKeyService,
	agentSvc *service.AgentService,
	auditSvc *service.AuditService,
	backchannelSvc *service.BackchannelService,
	dpopVerifier *dpop.Verifier,
	delegationSvc *service.DelegationService,
	jwksSvc *signing.JWKSService,
	signingCredSvc *service.SigningCredentialService,
	db *bun.DB,
	issuer string,
) *API {
	return &API{
		identitySvc:          identitySvc,
		credSvc:              credSvc,
		credentialPolicySvc:  credentialPolicySvc,
		attestationSvc:       attestationSvc,
		attestationPolicySvc: attestationPolicySvc,
		proofSvc:             proofSvc,
		oauthSvc:             oauthSvc,
		oauthClientSvc:       oauthClientSvc,
		signalSvc:            signalSvc,
		apiKeySvc:            apiKeySvc,
		agentSvc:             agentSvc,
		auditSvc:             auditSvc,
		backchannelSvc:       backchannelSvc,
		dpopVerifier:         dpopVerifier,
		delegationSvc:        delegationSvc,
		jwksSvc:              jwksSvc,
		signingCredSvc:       signingCredSvc,
		db:                   db,
		issuer:               issuer,
		startTime:            time.Now(),
	}
}

// NewHumaAPI creates a Huma API on the given chi router with goccy/go-json codec.
func NewHumaAPI(router chi.Router) huma.API {
	return humachi.New(router, zeroidHumaConfig())
}

// NewHumaAPISpecless creates a huma API that does NOT register the OpenAPI /
// docs / schemas routes. Use it for a secondary route group mounted on a router
// that already serves the canonical spec (e.g. the public agent self-service
// group sits on the same root router as RegisterPublic). Without this, the
// secondary instance's /openapi.json would shadow the canonical one
// (chi last-registration wins), dropping the public OAuth paths from the spec.
// Routes registered here are documented via the service contract + capability
// spec rather than this instance's (absent) spec.
func NewHumaAPISpecless(router chi.Router) huma.API {
	config := zeroidHumaConfig()
	config.OpenAPIPath = ""
	config.DocsPath = ""
	config.SchemasPath = ""
	return humachi.New(router, config)
}

func zeroidHumaConfig() huma.Config {
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

	// Huma's schema validator echoes the offending request body back in
	// ErrorDetail.Value on every failure path (unexpected property, missing
	// required field, etc.) — see danielgtaylor/huma/v2 validate.go, the
	// res.Add(path, m, ...) calls pass the whole parent object, not just the
	// field in question. On the credential-bearing OAuth endpoints that
	// reflects the caller's token/secret straight into the response (and
	// anything downstream that logs it). Redact it there; leave it intact
	// elsewhere, where echoing the bad value back is legitimate debugging aid.
	config.Transformers = append(config.Transformers, redactErrorValues(
		"/oauth2/token",
		"/oauth2/token/introspect",
		"/oauth2/token/revoke",
		"/oauth2/bc-authorize",
	))

	return config
}

// redactErrorValues returns a huma.Transformer that blanks every
// huma.ErrorDetail.Value on responses to the given paths, so validation
// failures never echo submitted credential material back to the caller (or
// into anything that logs the response body).
func redactErrorValues(paths ...string) huma.Transformer {
	redact := make(map[string]bool, len(paths))
	for _, p := range paths {
		redact[p] = true
	}
	return func(ctx huma.Context, status string, v any) (any, error) {
		if !redact[ctx.Operation().Path] {
			return v, nil
		}
		if em, ok := v.(*huma.ErrorModel); ok {
			for _, detail := range em.Errors {
				if detail != nil && detail.Value != nil {
					detail.Value = "[redacted]"
				}
			}
		}
		return v, nil
	}
}

// prmURL returns the absolute URL of this server's RFC 9728 Protected
// Resource Metadata document. Centralized so the value emitted in
// WWW-Authenticate breadcrumbs (RFC 9728 §5.1) stays in lockstep with the
// PRM endpoint's registered path.
func (a *API) prmURL() string {
	return a.issuer + "/.well-known/oauth-protected-resource"
}

// RegisterPublic registers endpoints that require no authentication:
// health, well-known, OAuth2 endpoints (token, revoke), and forward-auth verify.
// The /oauth2/register endpoints (RFC 7591/7592) live here too — they enforce
// their own intrinsic auth (initial-access-token or registration_access_token)
// per request, so they are not gated by the admin middleware.
func (a *API) RegisterPublic(api huma.API, router chi.Router) {
	a.registerHealthRoutes(api)
	a.registerWellKnownRoutes(api)
	a.registerSigningJWKSRoute(api)
	a.registerOAuthRoutes(api)
	a.registerDynamicRegistrationRoutes(api)
	a.registerAuthVerifyRoute(router)
	a.registerAuthorizeRoute(router)
}

// SetPrincipalResolverFunc wires the PrincipalResolver chain walker
// from the top-level Server into this API. Called by Server.NewServer
// once after API construction; not part of the public deployer API
// (deployers call Server.RegisterPrincipalResolver instead, which
// updates the registry that this function reads from).
func (a *API) SetPrincipalResolverFunc(fn PrincipalResolverFunc) {
	a.resolvePrincipal = fn
}

// SetCIMDEnabled records whether CIMD (Client ID Metadata Documents) resolution
// is active on this deployment, so the OAuth 2.0 Authorization Server Metadata
// document advertises client_id_metadata_document_supported accordingly. Called
// by Server.NewServer from cfg.CIMD.Enabled.
func (a *API) SetCIMDEnabled(enabled bool) {
	a.cimdEnabled = enabled
}

// SetCIMDPublishersVetted records whether cimd.allowed_domains is in force,
// which decides whether a CIMD client may be redirected to — its error
// redirect per RFC 6749 §4.1.2.1, and the interactive-login redirect.
//
// Both are refused for a self-asserted client by default because a CIMD
// document's redirect_uris are attacker-CHOSEN, not merely attacker-supplied:
// with no allow-list, any public HTTPS host can publish one. An allow-list is
// the deployer saying which hosts may publish, which restores the vetting
// §4.1.2.1's redirect rule assumes — so the refusal lifts with it.
//
// Called by Server.NewServer with CIMDService.AllowedDomainCount() > 0. A bool
// rather than a predicate because the allow-list comes from config and cannot
// change after construction, unlike the resolver registry.
func (a *API) SetCIMDPublishersVetted(vetted bool) {
	a.cimdPublishersVetted = vetted
}

// refusesRedirectTo reports whether client is a destination this deployment
// declines to redirect a user agent to — a self-asserted (CIMD) client whose
// publishing host nobody vetted. The single predicate behind both
// failAuthorize's §4.1.2.1 carve-out and redirectToInteractiveLogin's refusal,
// so the two cannot drift: they answer the same question about the same client.
func (a *API) refusesRedirectTo(client *domain.OAuthClient) bool {
	return client.SelfAsserted() && !a.cimdPublishersVetted
}

// SetAuthorizationCodeAvailable records a predicate reporting whether
// /oauth2/authorize can serve a request on this deployment.
//
// AS metadata is a promise. ZeroID previously advertised
// authorization_code and client_id_metadata_document_supported
// unconditionally while /oauth2/authorize answered 503 for every
// deployment that registered no PrincipalResolver — and an MCP client
// that believed the metadata skipped CIMD and fell back to dynamic client
// registration (#263). Discovery must not name a flow the endpoint cannot
// complete.
//
// The predicate gates the endpoint as well as the document: authorizeHandler
// answers 503 when it reports false, on both GET and POST. Editing only the
// metadata would leave a deployer who turned the flow off still serving it.
//
// A predicate rather than a bool because RegisterPrincipalResolver is
// documented as safe to call after NewServer.
func (a *API) SetAuthorizationCodeAvailable(fn func() bool) {
	a.authorizationCodeAvailable = fn
}

// canServeAuthorizationCode reports the predicate's answer, defaulting to
// true when no predicate was set.
func (a *API) canServeAuthorizationCode() bool {
	return a.authorizationCodeAvailable == nil || a.authorizationCodeAvailable()
}

// SetInteractiveLoginURL records where to send a user agent when a
// PrincipalResolver reports ErrPrincipalInteractionRequired. See
// Server.SetInteractiveLoginURL for the contract.
func (a *API) SetInteractiveLoginURL(fn func(*service.AuthorizeRequest) string) {
	a.interactiveLoginURL = fn
}

// RegisterAdmin registers admin/management endpoints:
// identities, credentials, policies, attestation, signals, oauth clients, proof verify.
// These run on the admin port which is protected at the network layer.
func (a *API) RegisterAdmin(api huma.API, router chi.Router) {
	a.registerIdentityRoutes(api)
	a.registerCredentialPolicyRoutes(api)
	a.registerCredentialRoutes(api)
	a.registerAttestationRoutes(api)
	a.registerAttestationPolicyRoutes(api)
	a.registerOAuthClientRoutes(api)
	a.registerAPIKeyRoutes(api)
	a.registerAgentRoutes(api)
	a.registerSignalRoutes(api, router)
	a.registerProofVerifyRoute(api)
	a.registerAuditRoutes(api)
	a.registerBackchannelAdminRoutes(api)
	a.registerExpiringSoonRoute(api)
	a.registerSigningCredentialRoutes(api)
	a.registerDelegationRoutes(api)
	a.registerObservedResourceRoutes(api)
}

// RegisterAgentAuth registers endpoints requiring agent-auth middleware (proof generation).
// These run on the admin port behind an additional agent JWT verification layer.
func (a *API) RegisterAgentAuth(api huma.API) {
	a.registerProofGenerateRoute(api)
}

// RegisterAgentSelfService registers endpoints an agent calls with its OWN
// access token (agent-auth middleware) rather than the internal service secret.
// Unlike RegisterAgentAuth (proof generation), these are meant to be mounted on
// the PUBLIC router so they are reachable on the public ingress — the deployer
// wraps them in AgentAuthMiddleware, and tenant/identity come from token claims.
func (a *API) RegisterAgentSelfService(api huma.API) {
	a.registerAgentSelfServiceRoute(api)
}
