package aauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/middleware"
	"github.com/highflame-ai/zeroid/internal/service"
	"github.com/highflame-ai/zeroid/pkg/dpop"
)

// Paths the Agent Provider serves. /ap/token and /ap/jwks.json follow
// aauth-go's agentprovider defaults; the metadata path is fixed by the spec.
const (
	PathToken    = "/ap/token"
	PathJWKS     = "/ap/jwks.json"
	PathMetadata = "/.well-known/" + AgentMetadataDWK
)

// maxBootstrapBody bounds the /ap/token body: one platform JWT and little else.
const maxBootstrapBody = 64 << 10

// assertionClockSkew outlives a redemption record past its assertion's exp by
// the skew the shared single-use store allows.
const assertionClockSkew = 60 * time.Second

// minAgentTokenTTL is the refresh margin: an agent refreshes its agent token
// when fewer than five minutes remain (bootstrap draft, Refresh Patterns).
const minAgentTokenTTL = 300

// DefaultAgentTokenTTL is the agent token's lifetime when none is configured:
// the 15 minutes ZeroID gives every externally authenticated token (ADR 0042
// D9), inside the bootstrap draft's 15–30 minute range for higher-assurance
// deployments.
const DefaultAgentTokenTTL = 15 * time.Minute

// Config configures the Agent Provider.
type Config struct {
	// Issuer is ZeroID's issuer. It is also the Agent Provider's issuer and
	// must be an AAuth server identifier: https, host only.
	Issuer string
	// SigningKeyPath is a PKCS#8 PEM Ed25519 private key. Required.
	SigningKeyPath string
	// SigningKeyID is the key's kid; empty means its thumbprint.
	SigningKeyID string
	// AgentTokenTTL is the agent token's lifetime, held to the identity's
	// credential policy. Zero means DefaultAgentTokenTTL.
	AgentTokenTTL time.Duration
	// Name is the display name in the metadata document. Optional.
	Name string
}

// Deps are the ZeroID services the Agent Provider builds on.
type Deps struct {
	OAuth       *service.OAuthService
	Credentials *service.CredentialService
	Identities  *service.IdentityService
	DB          *bun.DB
}

// Provider is ZeroID's AAuth Agent Provider.
type Provider struct {
	cfg         Config
	authority   string // the issuer's host: the domain of every agent identifier
	key         *signingKey
	oauth       *service.OAuthService
	creds       *service.CredentialService
	identities  *service.IdentityService
	redemptions *redemptions
	now         func() time.Time
}

// New builds the Agent Provider. It refuses to start without a usable key or
// with an issuer that is not an AAuth server identifier: there is no
// ephemeral fallback.
func New(cfg Config, deps Deps) (*Provider, error) {
	host, err := ServerIdentifierHost(cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("aauth: token.issuer %q is not an AAuth server identifier: %w", cfg.Issuer, err)
	}
	if cfg.SigningKeyPath == "" {
		return nil, errors.New("aauth: signing_key_path is required")
	}
	key, err := loadSigningKey(cfg.SigningKeyPath, cfg.SigningKeyID)
	if err != nil {
		return nil, fmt.Errorf("aauth: %w", err)
	}
	if deps.OAuth == nil || deps.Credentials == nil || deps.Identities == nil || deps.DB == nil {
		return nil, errors.New("aauth: missing dependencies")
	}
	if cfg.AgentTokenTTL <= 0 {
		cfg.AgentTokenTTL = DefaultAgentTokenTTL
	}
	p := &Provider{
		cfg:         cfg,
		authority:   host,
		key:         key,
		oauth:       deps.OAuth,
		creds:       deps.Credentials,
		identities:  deps.Identities,
		redemptions: &redemptions{db: deps.DB},
		now:         time.Now,
	}
	p.registerBridge(deps.OAuth)
	return p, nil
}

// ServerIdentifierHost checks s against the AAuth server identifier rules
// (https, scheme and host only: no port, path, query, fragment or trailing
// slash, lower case) and returns its host.
func ServerIdentifierHost(s string) (string, error) {
	u, err := url.Parse(s)
	switch {
	case err != nil:
		return "", err
	case u.Scheme != "https":
		return "", errors.New("not https")
	case u.Host == "" || u.Port() != "" || strings.Contains(u.Host, ":"):
		return "", errors.New("no host, or a port")
	case u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil || strings.HasSuffix(s, "/"):
		return "", errors.New("more than scheme and host")
	case s != strings.ToLower(s):
		return "", errors.New("not lower case")
	}
	return u.Host, nil
}

// Mount registers the Agent Provider's routes. (The bridge grant is
// registered on the token endpoint by New.)
func (p *Provider) Mount(r chi.Router) {
	r.Post(PathToken, p.handleToken)
	r.Get(PathJWKS, p.handleJWKS)
	r.Get(PathMetadata, p.handleMetadata)
}

func (p *Provider) handleMetadata(w http.ResponseWriter, _ *http.Request) {
	doc := map[string]any{
		"issuer":                p.cfg.Issuer,
		"jwks_uri":              p.cfg.Issuer + PathJWKS,
		"accept_signature_algs": SupportedAlgs,
	}
	if p.cfg.Name != "" {
		doc["name"] = p.cfg.Name
	}
	writeCacheableJSON(w, doc)
}

func (p *Provider) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	writeCacheableJSON(w, p.key.jwks())
}

func writeCacheableJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(v)
}

// requestAuthority is @authority as this server was reached, from the URL
// RequestURLMiddleware recorded (which honours the configured forwarded-header
// trust), lower case and without a default port.
//
// :443 is dropped whatever scheme was recorded: the Agent Provider is https
// by definition, and a TLS-terminating proxy whose forwarded scheme isn't
// trusted still forwards Host with it.
func requestAuthority(r *http.Request) string {
	host := r.Host
	if eff := middleware.EffectiveRequestURL(r.Context()); eff != "" {
		if u, err := url.Parse(eff); err == nil && u.Host != "" {
			host = u.Host
		}
	}
	host = strings.ToLower(host)
	if h, port, ok := strings.Cut(host, ":"); ok && port == "443" {
		host = h
	}
	return host
}

// bootstrapRequest is the /ap/token body. attestation is the workload's
// platform token: the member aauth-go's agentprovider client sends evidence in.
type bootstrapRequest struct {
	Attestation string `json:"attestation"`
}

// handleToken is POST /ap/token: an hwk-signed request carrying a platform
// token in "attestation" returns an agent token bound to the hwk key.
func (p *Provider) handleToken(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBootstrapBody+1))
	if err != nil || len(body) > maxBootstrapBody {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "the request body is unreadable or too large")
		return
	}

	authority := requestAuthority(r)
	if authority != p.authority {
		WriteSigError(w, sigErr(ErrCodeInvalidSignature, "this Agent Provider is %s", p.authority))
		return
	}
	verified, err := VerifyRequest(r, body, VerifyOptions{
		Now:                 p.now(),
		Authority:           authority,
		RequireBodyCoverage: true,
		Schemes:             []string{"hwk"},
		ResolveKey: func(_ string, params map[string]any) (JWK, error) {
			return ResolveHWK(params)
		},
	})
	if err != nil {
		var se *SigError
		if !errors.As(err, &se) {
			se = sigErr(ErrCodeInvalidSignature, "%v", err)
		}
		WriteSigError(w, se)
		return
	}

	var req bootstrapRequest
	if err := json.Unmarshal(body, &req); err != nil || req.Attestation == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", `the body must be {"attestation": "<platform token>"}`)
		return
	}

	agentToken, ttl, err := p.bootstrap(r.Context(), req.Attestation, verified.Key)
	if err != nil {
		var refusal *bootstrapRefusal
		if errors.As(err, &refusal) {
			// After the signature verified, so 403 and no Signature-Error.
			status := http.StatusForbidden
			if refusal.status != 0 {
				status = refusal.status
			}
			if refusal.retryAfter > 0 {
				w.Header().Set("Retry-After", fmt.Sprint(refusal.retryAfter))
			}
			writeOAuthError(w, status, refusal.code, refusal.description)
			return
		}
		log.Error().Err(err).Msg("aauth: bootstrap failed")
		writeOAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "agent token issuance is temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"agent_token": agentToken, "expires_in": ttl})
}

// bootstrapRefusal is a request refused for what it carries, not a server
// failure.
type bootstrapRefusal struct {
	code, description string
	cause             error
	// status overrides the default 403; retryAfter, when set, is sent as
	// Retry-After (seconds).
	status, retryAfter int
}

func (e *bootstrapRefusal) Error() string { return e.code + ": " + e.description }
func (e *bootstrapRefusal) Unwrap() error { return e.cause }

// notAccepted is the one answer for every refusal before the assertion's
// signature has verified, whatever the reason: a distinct answer would tell
// an unsigned probe which issuers and claim values an account trusts. The
// reason goes to the log. (The hwk signature proves only that the caller
// holds a key it generated, which anyone can.)
func notAccepted(cause error) error {
	return &bootstrapRefusal{code: "access_denied", description: "the attestation was not accepted", cause: cause}
}

// refusalOrFailure keeps an OAuth error's 4xx as a refusal with its own code
// and description, and anything else as a server failure.
func refusalOrFailure(err error) error {
	var oe *service.OAuthError
	if errors.As(err, &oe) && oe.HTTPStatus < http.StatusInternalServerError {
		return &bootstrapRefusal{code: oe.Code, description: oe.Description, cause: err}
	}
	return err
}

// bootstrap verifies the attestation, binds it to key, and mints the agent
// token through IssueCredential. It returns the token and its lifetime in
// seconds.
func (p *Provider) bootstrap(ctx context.Context, attestation string, key JWK) (string, int, error) {
	jkt, err := key.Thumbprint()
	if err != nil {
		return "", 0, &bootstrapRefusal{code: "invalid_request", description: "the signing key has no thumbprint", cause: err}
	}

	entry, ok, err := p.oauth.LookupWorkloadIssuer(ctx, attestation)
	if err != nil {
		if failure := refusalOrFailure(err); !isRefusal(failure) {
			return "", 0, failure
		}
		return "", 0, notAccepted(err)
	}
	if !ok {
		return "", 0, notAccepted(errors.New("the attestation's issuer is not a workload issuer"))
	}
	wa, err := p.oauth.VerifyWorkloadAssertion(ctx, attestation, entry, "attestation", nil)
	if err != nil {
		if failure := refusalOrFailure(err); !isRefusal(failure) {
			return "", 0, failure
		}
		return "", 0, notAccepted(err)
	}

	claim, age, err := p.redemptions.claim(ctx, wa.ReplayKey, jkt, wa.ExpiresAt.Add(assertionClockSkew))
	if err != nil {
		return "", 0, fmt.Errorf("claiming the attestation: %w", err)
	}
	switch claim {
	case claimRefused:
		return "", 0, &bootstrapRefusal{code: "invalid_grant", description: "the attestation was already redeemed by another key"}
	case claimPending:
		if age < pendingInFlight {
			return "", 0, &bootstrapRefusal{code: "temporarily_unavailable", status: http.StatusServiceUnavailable, retryAfter: 1,
				description: "a redemption of this attestation by this key is still in progress; retry"}
		}
		// Claimed long ago and never finished: the request died mid-flight.
		return "", 0, &bootstrapRefusal{code: "invalid_grant",
			description: "an earlier redemption of this attestation by this key did not complete; retry with a fresh platform token"}
	case claimRefusedEarlier:
		return "", 0, &bootstrapRefusal{code: "invalid_grant",
			description: "an earlier redemption of this attestation by this key was refused; retry with a fresh platform token"}
	case claimExpired:
		return "", 0, &bootstrapRefusal{code: "invalid_grant", description: "the attestation has expired"}
	case claimFresh:
		if err := p.oauth.SpendWorkloadAssertion(ctx, wa); err != nil {
			if errors.Is(err, dpop.ErrReplay) {
				// Spent at the token endpoint. The claim is marked refused,
				// so every later redemption is refused too.
				if mErr := p.redemptions.refuse(ctx, wa.ReplayKey); mErr != nil {
					log.Warn().Err(mErr).Msg("aauth: could not record a refused redemption")
				}
				return "", 0, &bootstrapRefusal{code: "invalid_grant", description: "the attestation has already been used"}
			}
			p.forget(ctx, wa)
			return "", 0, fmt.Errorf("spending the attestation: %w", err)
		}
	}
	fresh := claim == claimFresh
	// A refusal after a fresh claim is recorded, so the same key is refused
	// at once next time instead of being told to retry.
	refused := func(err error) error {
		if fresh && isRefusal(err) {
			if mErr := p.redemptions.refuse(ctx, wa.ReplayKey); mErr != nil {
				log.Warn().Err(mErr).Msg("aauth: could not record a refused redemption")
			}
		}
		return err
	}
	// cleanup undoes a fresh claim after a server-side failure minted
	// nothing, so a retry with the same platform token works.
	cleanup := func() {
		if fresh {
			p.oauth.ReleaseWorkloadAssertion(ctx, wa)
			p.forget(ctx, wa)
		}
	}

	identity, err := p.oauth.ResolveWorkloadAgent(ctx, wa, string(domain.GrantTypeAAuthAgent))
	if err != nil {
		failure := refusalOrFailure(err)
		if !isRefusal(failure) {
			cleanup()
		}
		return "", 0, refused(failure)
	}
	policy, err := p.oauth.ResolveWorkloadPolicy(ctx, identity)
	if err != nil {
		cleanup()
		return "", 0, err
	}
	ttl := int(p.cfg.AgentTokenTTL / time.Second)
	if policy != nil && policy.MaxTTLSeconds > 0 && policy.MaxTTLSeconds < ttl {
		ttl = policy.MaxTTLSeconds
	}
	if ttl <= minAgentTokenTTL {
		// An agent refreshes when fewer than five minutes remain, so a token
		// of five minutes or less is due for refresh as it is issued, and the
		// agent would loop on /ap/token. A refusal keeps the attestation
		// spent, as every refusal does.
		return "", 0, refused(&bootstrapRefusal{code: "access_denied",
			description: fmt.Sprintf("the identity's credential policy allows tokens of at most %ds; an agent token needs over %ds", ttl, minAgentTokenTTL)})
	}
	sub := "aauth:" + identity.ID + "@" + p.authority
	issued, _, err := p.creds.IssueCredential(ctx, service.IssueRequest{
		Identity:         identity,
		IdentityPolicyID: policyID(policy),
		TTL:              ttl,
		GrantType:        domain.GrantTypeAAuthAgent,
		// Recorded on the row as the key the token is bound to (its cnf.jwk).
		DPoPKeyThumbprint: jkt,
		AgentTokenSigner: func(jti string, iat, exp time.Time) (string, error) {
			return p.key.sign(p.cfg.Issuer, sub, key, jti, iat, exp)
		},
	})
	if err != nil {
		if errors.Is(err, service.ErrPolicyViolation) || errors.Is(err, service.ErrScopesNotAllowed) ||
			errors.Is(err, domain.ErrIdentityNotUsable) || errors.Is(err, domain.ErrIdentityExpired) {
			return "", 0, refused(&bootstrapRefusal{code: "access_denied", description: err.Error(), cause: err})
		}
		cleanup()
		return "", 0, fmt.Errorf("issuing the agent token: %w", err)
	}
	if issued.ExpiresIn <= minAgentTokenTTL {
		// Clamped further inside issuance (token.max_ttl, or an identity near
		// its expiry). The token is valid; the agent will refresh at once.
		log.Warn().Int("expires_in", issued.ExpiresIn).Str("identity_id", identity.ID).
			Msg("aauth: agent token issued inside the five-minute refresh margin")
	}
	if fresh {
		if err := p.redemptions.confirm(ctx, wa.ReplayKey); err != nil {
			// The token is issued; only a repeat redemption by this key is lost.
			log.Warn().Err(err).Msg("aauth: could not confirm a redemption; a repeat by the same key will be refused")
		}
	}
	return issued.AccessToken, issued.ExpiresIn, nil
}

func isRefusal(err error) bool {
	var r *bootstrapRefusal
	return errors.As(err, &r)
}

func policyID(p *domain.CredentialPolicy) string {
	if p == nil {
		return ""
	}
	return p.ID
}

func (p *Provider) forget(ctx context.Context, wa *service.WorkloadAssertion) {
	if err := p.redemptions.forget(ctx, wa.ReplayKey); err != nil {
		log.Warn().Err(err).Msg("aauth: could not forget a failed redemption; a retry by the same key will be refused")
	}
}
