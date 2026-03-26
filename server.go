package zeroid

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	gojson "github.com/goccy/go-json"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/database"
	"github.com/highflame-ai/zeroid/internal/handler"
	internalMiddleware "github.com/highflame-ai/zeroid/internal/middleware"
	"github.com/highflame-ai/zeroid/internal/service"
	"github.com/highflame-ai/zeroid/internal/signing"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
	"github.com/highflame-ai/zeroid/internal/telemetry"
	"github.com/highflame-ai/zeroid/internal/worker"
)

// middlewareHolder stores an optional middleware in a thread-safe way.
// The middleware closure is registered at router-build time; the actual function
// is set later (before Start) via a setter method.
type middlewareHolder struct {
	mu sync.RWMutex
	fn func(http.Handler) http.Handler
}

// Server is the main ZeroID server.
//
// Single port, two route groups:
//   - Public routes (/oauth2/*, /.well-known/*, /health, /ready): No authentication.
//     These are the token endpoints agents and SDKs call directly.
//   - Admin routes (/api/v1/*): Identity management, credential policies,
//     attestation, signals. No built-in auth by default — protect at the
//     network layer or use the AdminAuth hook.
type Server struct {
	cfg    Config
	db     *bun.DB
	router chi.Router
	http   *http.Server

	// Services
	identitySvc         *service.IdentityService
	credentialSvc       *service.CredentialService
	credentialPolicySvc *service.CredentialPolicyService
	attestationSvc      *service.AttestationService
	proofSvc            *service.ProofService
	oauthSvc            *service.OAuthService
	oauthClientSvc      *service.OAuthClientService
	signalSvc           *service.SignalService
	apiKeySvc           *service.APIKeyService
	agentSvc            *service.AgentService
	jwksSvc             *signing.JWKSService
	refreshTokenSvc     *service.RefreshTokenService

	// Cleanup
	cleanupWorker *worker.CleanupWorker
	workerCancel  context.CancelFunc

	// Extensibility
	mu              sync.RWMutex
	claimsEnrichers []ClaimsEnricher
	adminAuthState  *middlewareHolder
	globalMWState   *middlewareHolder
}

// NewServer initializes all ZeroID subsystems: database, migrations, signing keys,
// repositories, services, handlers, and the HTTP router.
func NewServer(cfg Config) (*Server, error) {
	initLogging(cfg.Logging.Level)

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	log.Info().Msg("Initializing ZeroID server")

	// Initialize OpenTelemetry.
	if err := telemetry.Init(telemetry.Config{
		Enabled:      cfg.Telemetry.Enabled,
		Endpoint:     cfg.Telemetry.Endpoint,
		Insecure:     cfg.Telemetry.Insecure,
		ServiceName:  cfg.Telemetry.ServiceName,
		SamplingRate: cfg.Telemetry.SamplingRate,
	}); err != nil {
		log.Warn().Err(err).Msg("Failed to initialize telemetry — continuing without observability")
	}

	// Initialize database.
	db, err := initDatabase(cfg.Database.URL, cfg.Database.MaxOpenConns, cfg.Database.MaxIdleConns)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	// Run migrations unless the deployer has opted out.
	autoMigrate := cfg.Database.AutoMigrate == nil || *cfg.Database.AutoMigrate
	if autoMigrate {
		if err := database.RunMigrations(db); err != nil {
			return nil, fmt.Errorf("failed to run database migrations: %w", err)
		}
	} else {
		log.Info().Msg("Auto-migrate disabled — deployer manages schema migrations")
	}

	// Initialize JWKS service (loads ECDSA P-256 key pair).
	jwksSvc, err := signing.NewJWKSService(cfg.Keys.PrivateKeyPath, cfg.Keys.PublicKeyPath, cfg.Keys.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize JWKS service — run 'make setup-keys': %w", err)
	}

	// Load RSA keys for RS256 signing (optional — required for api_key grant).
	if cfg.Keys.RSAPrivateKeyPath != "" && cfg.Keys.RSAPublicKeyPath != "" {
		if err := jwksSvc.LoadRSAKeys(cfg.Keys.RSAPrivateKeyPath, cfg.Keys.RSAPublicKeyPath, cfg.Keys.RSAKeyID); err != nil {
			return nil, fmt.Errorf("failed to load RSA keys for RS256 signing: %w", err)
		}
	} else {
		log.Info().Msg("RSA keys not configured — api_key grant type will be unavailable")
	}

	// Initialize repositories.
	identityRepo := postgres.NewIdentityRepository(db)
	credentialRepo := postgres.NewCredentialRepository(db)
	attestationRepo := postgres.NewAttestationRepository(db)
	signalRepo := postgres.NewSignalRepository(db)
	proofRepo := postgres.NewProofRepository(db)
	oauthClientRepo := postgres.NewOAuthClientRepository(db)
	credentialPolicyRepo := postgres.NewCredentialPolicyRepository(db)
	apiKeyRepo := postgres.NewAPIKeyRepository(db)
	refreshTokenRepo := postgres.NewRefreshTokenRepository(db)

	// Initialize services.
	identitySvc := service.NewIdentityService(identityRepo, cfg.WIMSEDomain)
	credentialPolicySvc := service.NewCredentialPolicyService(credentialPolicyRepo)
	credentialSvc := service.NewCredentialService(credentialRepo, jwksSvc, credentialPolicySvc, attestationRepo, cfg.Token.Issuer, cfg.Token.DefaultTTL, cfg.Token.MaxTTL)
	attestationSvc := service.NewAttestationService(attestationRepo, credentialSvc, identitySvc)
	oauthClientSvc := service.NewOAuthClientService(oauthClientRepo)
	apiKeySvc := service.NewAPIKeyService(apiKeyRepo, credentialPolicySvc, identitySvc)
	agentSvc := service.NewAgentService(identitySvc, apiKeySvc, apiKeyRepo)
	refreshTokenSvc := service.NewRefreshTokenService(refreshTokenRepo, db)
	authCodeIssuer := cfg.Token.AuthCodeIssuer
	if authCodeIssuer == "" {
		authCodeIssuer = cfg.Token.Issuer
	}
	oauthSvc := service.NewOAuthService(credentialSvc, identitySvc, oauthClientSvc, apiKeyRepo, jwksSvc, refreshTokenSvc, service.OAuthServiceConfig{
		Issuer:         cfg.Token.Issuer,
		WIMSEDomain:    cfg.WIMSEDomain,
		HMACSecret:     cfg.Token.HMACSecret,
		AuthCodeIssuer: authCodeIssuer,
	})
	proofSvc := service.NewProofService(jwksSvc, proofRepo, cfg.Token.Issuer)
	signalSvc := service.NewSignalService(signalRepo, credentialRepo)

	// Create shared API handler.
	apiHandler := handler.NewAPI(
		identitySvc, credentialSvc, credentialPolicySvc,
		attestationSvc, proofSvc, oauthSvc, oauthClientSvc,
		signalSvc, apiKeySvc, agentSvc, jwksSvc, db,
		cfg.Token.Issuer, cfg.Token.BaseURL,
	)

	// Shared middleware state — closures reference these holders; the actual functions
	// are set after NewServer returns (before Start) via setter methods.
	authState := &middlewareHolder{}
	globalMW := &middlewareHolder{}

	// ── Single router, two route groups ──────────────────────────────────────
	r := chi.NewRouter()

	// Global middleware.
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(requestValidationMiddleware)
	r.Use(errorRecoveryMiddleware)
	r.Use(structuredLoggingMiddleware)
	r.Use(chimiddleware.Recoverer)

	// Optional global middleware — runs on ALL routes (public + admin).
	// Set via Server.Use() after NewServer. Checked at request time.
	// Use this to annotate request context (e.g. trusted service identity from headers)
	// without blocking unauthenticated callers.
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			globalMW.mu.RLock()
			mw := globalMW.fn
			globalMW.mu.RUnlock()
			if mw != nil {
				mw(next).ServeHTTP(w, req)
				return
			}
			next.ServeHTTP(w, req)
		})
	})

	// Public routes — no auth.
	// /health, /ready, /.well-known/*, /oauth2/token, /oauth2/token/introspect, /oauth2/token/revoke, /oauth2/token/verify
	humaPublic := handler.NewHumaAPI(r)
	apiHandler.RegisterPublic(humaPublic, r)

	// Admin routes — /api/v1/*
	// No built-in auth by default. Protected at the network layer or via AdminAuth hook.
	r.Group(func(r chi.Router) {
		// Optional admin auth — checked at request time so it can be set after NewServer.
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				authState.mu.RLock()
				auth := authState.fn
				authState.mu.RUnlock()
				if auth != nil {
					auth(next).ServeHTTP(w, req)
					return
				}
				next.ServeHTTP(w, req)
			})
		})

		// Tenant context extraction from X-Account-ID / X-Project-ID headers.
		r.Use(internalMiddleware.TenantContextMiddleware)

		humaAdmin := handler.NewHumaAPI(r)
		apiHandler.RegisterAdmin(humaAdmin, r)

		// Agent-auth sub-group for proof generation (requires agent JWT).
		r.Group(func(r chi.Router) {
			agentAuthCfg := internalMiddleware.AgentAuthConfig{
				PublicKey: jwksSvc.PublicKey(),
				Issuer:    cfg.Token.Issuer,
			}
			r.Use(internalMiddleware.AgentAuthMiddleware(agentAuthCfg))

			humaAgentAuth := handler.NewHumaAPI(r)
			apiHandler.RegisterAgentAuth(humaAgentAuth)
		})
	})

	// Parse timeouts.
	readTimeout := parseDurationOrDefault(cfg.Server.ReadTimeout, 15*time.Second)
	writeTimeout := parseDurationOrDefault(cfg.Server.WriteTimeout, 15*time.Second)
	idleTimeout := parseDurationOrDefault(cfg.Server.IdleTimeout, 60*time.Second)

	srv := &Server{
		cfg:                 cfg,
		db:                  db,
		router:              r,
		identitySvc:         identitySvc,
		credentialSvc:       credentialSvc,
		credentialPolicySvc: credentialPolicySvc,
		attestationSvc:      attestationSvc,
		proofSvc:            proofSvc,
		oauthSvc:            oauthSvc,
		oauthClientSvc:      oauthClientSvc,
		signalSvc:           signalSvc,
		apiKeySvc:           apiKeySvc,
		agentSvc:            agentSvc,
		jwksSvc:             jwksSvc,
		refreshTokenSvc:     refreshTokenSvc,
		cleanupWorker:       worker.NewCleanupWorker(db, time.Hour),
		adminAuthState:      authState,
		globalMWState:       globalMW,
		http: &http.Server{
			Addr:         ":" + cfg.Server.Port,
			Handler:      r,
			ReadTimeout:  readTimeout,
			WriteTimeout: writeTimeout,
			IdleTimeout:  idleTimeout,
		},
	}

	return srv, nil
}

// Start starts the HTTP server and background workers. It blocks until a
// SIGINT/SIGTERM is received and then performs graceful shutdown.
func (s *Server) Start() error {
	// Start background workers.
	workerCtx, workerCancel := context.WithCancel(context.Background())
	s.workerCancel = workerCancel
	go s.cleanupWorker.Run(workerCtx)

	// Start HTTP server.
	errCh := make(chan error, 1)
	go func() {
		log.Info().Str("port", s.cfg.Server.Port).Msg("Starting ZeroID server")
		log.Info().Msg("  Public:  /health, /.well-known/*, /oauth2/*")
		log.Info().Msg("  Admin:   /api/v1/* (no built-in auth — protect at network layer)")
		if err := s.http.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Wait for shutdown signal or server error.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		s.workerCancel()
		return fmt.Errorf("server error: %w", err)
	case <-sigChan:
		log.Info().Msg("Shutdown signal received, shutting down gracefully...")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.cfg.Server.ShutdownTimeoutSeconds)*time.Second)
	defer cancel()

	if err := s.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown error: %w", err)
	}

	log.Info().Msg("Server shutdown complete")
	return nil
}

// Shutdown gracefully stops the server, workers, database, and telemetry.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.workerCancel != nil {
		s.workerCancel()
	}

	var firstErr error
	if err := s.http.Shutdown(ctx); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := s.db.Close(); err != nil && firstErr == nil {
		firstErr = err
	}

	telCtx, telCancel := context.WithTimeout(ctx, 5*time.Second)
	defer telCancel()
	if err := telemetry.Shutdown(telCtx); err != nil && firstErr == nil {
		firstErr = err
	}

	return firstErr
}

// RegisterGrant registers a custom OAuth2 grant type handler.
// The handler is called when the token endpoint receives a grant_type matching name.
func (s *Server) RegisterGrant(name string, handler GrantHandler) {
	s.oauthSvc.RegisterGrant(name, func(ctx context.Context, req service.TokenRequest) (*domain.AccessToken, error) {
		return handler(ctx, GrantRequest{
			GrantType:        req.GrantType,
			AccountID:        req.AccountID,
			ProjectID:        req.ProjectID,
			UserID:           req.UserID,
			UserEmail:        req.UserEmail,
			UserName:         req.UserName,
			ApplicationID:    req.ApplicationID,
			Scope:            req.Scope,
			AdditionalClaims: req.AdditionalClaims,
		})
	})
}

// ExternalPrincipalExchange issues an RS256 token for an externally-authenticated user.
// The caller (a trusted internal service) has already verified the user's identity and
// resolved tenant context. ZeroID trusts the caller and issues a token with the provided claims.
// This is the building block for custom grant types like "user_session".
func (s *Server) ExternalPrincipalExchange(ctx context.Context, req GrantRequest) (*domain.AccessToken, error) {
	return s.oauthSvc.ExternalPrincipalExchange(ctx, service.TokenRequest{
		GrantType:        req.GrantType,
		AccountID:        req.AccountID,
		ProjectID:        req.ProjectID,
		UserID:           req.UserID,
		UserEmail:        req.UserEmail,
		UserName:         req.UserName,
		ApplicationID:    req.ApplicationID,
		Scope:            req.Scope,
		AdditionalClaims: req.AdditionalClaims,
		TrustedService:   true,
	})
}

// OnClaimsIssue registers a claims enricher called during JWT issuance.
func (s *Server) OnClaimsIssue(enricher ClaimsEnricher) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.claimsEnrichers = append(s.claimsEnrichers, enricher)
}

// AdminAuth sets an optional authentication middleware for /api/v1/* admin routes.
// Can be called after NewServer and before Start — the middleware is checked at
// request time. When nil (default), admin routes have no built-in auth — protect
// them at the network layer (reverse proxy, VPN, firewall).
func (s *Server) AdminAuth(middleware AdminAuthMiddleware) {
	s.adminAuthState.mu.Lock()
	defer s.adminAuthState.mu.Unlock()
	s.adminAuthState.fn = middleware
}

// Use adds a global middleware that runs on ALL routes (public + admin).
// Unlike AdminAuth (which only protects admin routes), this middleware runs on
// every request including the public /oauth2/token endpoint.
//
// Use this to annotate request context without blocking — for example, extracting
// trusted service identity from headers so that TrustedServiceValidator can read it
// during external principal token exchange.
//
// Can be called after NewServer and before Start.
func (s *Server) Use(middleware func(http.Handler) http.Handler) {
	s.globalMWState.mu.Lock()
	defer s.globalMWState.mu.Unlock()
	s.globalMWState.fn = middleware
}

// SetTrustedServiceValidator sets the validator used during external principal
// token exchange (RFC 8693) to verify the caller is a trusted internal service.
// The validator reads from context (populated by deployer-provided global middleware
// via Server.Use). When nil (default), external principal exchange is disabled.
//
// Can be called after NewServer and before Start.
func (s *Server) SetTrustedServiceValidator(v TrustedServiceValidator) {
	s.oauthSvc.SetTrustedServiceValidator(func(ctx context.Context) (string, error) {
		return v(ctx)
	})
}

// Router returns the chi.Router for custom route mounting.
func (s *Server) Router() chi.Router {
	return s.router
}

// GetIdentity returns the identity with the given ID for the specified tenant.
// Returns an error if the identity is not found or does not belong to the tenant.
func (s *Server) GetIdentity(ctx context.Context, id, accountID, projectID string) (*domain.Identity, error) {
	return s.identitySvc.GetIdentity(ctx, id, accountID, projectID)
}

// EnsureClient registers an OAuth client if it doesn't exist, or updates it if the
// config has changed. Idempotent — safe to call on every startup.
// Does not regenerate client_secret on update (secrets are rotated explicitly).
func (s *Server) EnsureClient(ctx context.Context, cfg OAuthClientConfig) error {
	existing, err := s.oauthClientSvc.GetClientByClientID(ctx, cfg.ClientID)
	if err != nil {
		// Client doesn't exist — create it.
		_, _, regErr := s.oauthClientSvc.RegisterClient(ctx, service.RegisterClientRequest{
			ClientID:                cfg.ClientID,
			Name:                    cfg.Name,
			Description:             cfg.Description,
			Confidential:            cfg.Confidential,
			TokenEndpointAuthMethod: cfg.TokenEndpointAuthMethod,
			GrantTypes:              cfg.GrantTypes,
			Scopes:                  cfg.Scopes,
			RedirectURIs:            cfg.RedirectURIs,
			AccessTokenTTL:          cfg.AccessTokenTTL,
			RefreshTokenTTL:         cfg.RefreshTokenTTL,
			JWKSURI:                 cfg.JWKSURI,
			JWKS:                    cfg.JWKS,
			SoftwareID:              cfg.SoftwareID,
			SoftwareVersion:         cfg.SoftwareVersion,
			Contacts:                cfg.Contacts,
			Metadata:                cfg.Metadata,
		})

		return regErr
	}

	// Client exists — update mutable fields from config.
	// Secret is NOT touched (rotated explicitly via RotateSecret).
	updated := false

	if cfg.Name != "" && cfg.Name != existing.Name {
		existing.Name = cfg.Name
		updated = true
	}
	if cfg.Description != "" && cfg.Description != existing.Description {
		existing.Description = cfg.Description
		updated = true
	}
	if cfg.GrantTypes != nil && !slicesEqual(cfg.GrantTypes, existing.GrantTypes) {
		existing.GrantTypes = cfg.GrantTypes
		updated = true
	}
	if cfg.Scopes != nil && !slicesEqual(cfg.Scopes, existing.Scopes) {
		existing.Scopes = cfg.Scopes
		updated = true
	}
	if cfg.RedirectURIs != nil && !slicesEqual(cfg.RedirectURIs, existing.RedirectURIs) {
		existing.RedirectURIs = cfg.RedirectURIs
		updated = true
	}
	if cfg.AccessTokenTTL > 0 && cfg.AccessTokenTTL != existing.AccessTokenTTL {
		existing.AccessTokenTTL = cfg.AccessTokenTTL
		updated = true
	}
	if cfg.RefreshTokenTTL > 0 && cfg.RefreshTokenTTL != existing.RefreshTokenTTL {
		existing.RefreshTokenTTL = cfg.RefreshTokenTTL
		updated = true
	}

	if !updated {
		return nil
	}

	existing.UpdatedAt = time.Now()

	return s.oauthClientSvc.UpdateClient(ctx, existing)
}

// slicesEqual returns true if two string slices have the same elements in order.
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────────────────────────

func initLogging(logLevel string) {
	level, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)
	log.Logger = log.With().Caller().Logger()
}

func initDatabase(databaseURL string, maxOpenConns, maxIdleConns int) (*bun.DB, error) {
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(databaseURL)))

	if err := sqldb.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	sqldb.SetMaxOpenConns(maxOpenConns)
	sqldb.SetMaxIdleConns(maxIdleConns)
	sqldb.SetConnMaxLifetime(30 * time.Minute)
	sqldb.SetConnMaxIdleTime(5 * time.Minute)

	db := bun.NewDB(sqldb, pgdialect.New())

	if parsedURL, err := url.Parse(databaseURL); err == nil {
		log.Info().Str("host", parsedURL.Host).Str("database", parsedURL.Path).Msg("Database connection established")
	}

	return db, nil
}

func parseDurationOrDefault(s string, def time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil || d == 0 {
		return def
	}
	return d
}

// errorRecoveryMiddleware recovers from panics and returns a 500 JSON error response.
func errorRecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Error().
					Interface("panic", err).
					Str("method", r.Method).
					Str("path", r.RequestURI).
					Msg("Panic recovered in request handler")

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)

				errResp := domain.NewErrorResponse(
					http.StatusInternalServerError,
					domain.ErrCodeInternal,
					"Internal service error",
				)

				if reqID := chimiddleware.GetReqID(r.Context()); reqID != "" {
					errResp.WithRequestID(reqID)
				}

				_ = gojson.NewEncoder(w).Encode(errResp)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// requestValidationMiddleware limits request body size to 10 MiB and enforces
// application/json Content-Type on mutating requests (POST, PUT, PATCH).
func requestValidationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const maxBodySize = 10 * 1024 * 1024
		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			ct := r.Header.Get("Content-Type")
			// Allow missing Content-Type for SSE stream endpoint.
			if ct == "" && r.URL.Path != "/api/v1/signals/stream" {
				writeValidationError(w, r, "Content-Type header is required for "+r.Method+" requests")
				return
			}
			if ct != "" && !strings.HasPrefix(ct, "application/json") {
				writeValidationError(w, r, "Content-Type must be application/json, got: "+ct)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func writeValidationError(w http.ResponseWriter, r *http.Request, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	errResp := map[string]any{
		"error": map[string]any{
			"code":         http.StatusBadRequest,
			"internalCode": domain.ErrCodeBadRequest,
			"message":      msg,
			"status":       "BAD_REQUEST",
			"timestamp":    time.Now().UTC().Format(time.RFC3339),
		},
	}
	if reqID := chimiddleware.GetReqID(r.Context()); reqID != "" {
		errResp["error"].(map[string]any)["requestId"] = reqID
	}
	_ = gojson.NewEncoder(w).Encode(errResp)
}

// structuredLoggingMiddleware emits zerolog request/response log events.
func structuredLoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		requestID := chimiddleware.GetReqID(r.Context())

		log.Info().
			Str("request_id", requestID).
			Str("method", r.Method).
			Str("path", r.RequestURI).
			Str("remote_addr", r.RemoteAddr).
			Msg("request.start")

		ww := chimiddleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)

		duration := time.Since(start)
		logLevel := log.Info()
		if duration > time.Second {
			logLevel = log.Warn()
		}
		if ww.Status() >= 400 {
			logLevel = log.Error()
		}

		logLevel.
			Str("request_id", requestID).
			Str("method", r.Method).
			Str("path", r.RequestURI).
			Int("status", ww.Status()).
			Dur("duration", duration).
			Msg("request.complete")
	})
}
