package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/oautherror"
	"github.com/highflame-ai/zeroid/pkg/authjwt"
)

// FederatedExchangeRequest is the input to FederatedCredentialExchange — the
// Workload-Identity-Federation broker path (ADR 0028). A trusted internal
// service (the AI gateway) asks ZeroID to mint a short-lived, provider-audienced
// assertion for an agent it has already authenticated, so the assertion can be
// presented to the provider's WIF token endpoint and exchanged for a short-lived
// provider credential.
type FederatedExchangeRequest struct {
	AccountID string
	ProjectID string
	// SubjectWIMSE is the acting agent's SPIFFE/WIMSE id. It becomes the JWT
	// `sub` — the principal the provider's federation rule matches on.
	SubjectWIMSE string
	// ExternalID is the agent's stable external id, recorded as a claim for
	// audit correlation. Optional.
	ExternalID string
	// Audience is the provider audience to stamp (e.g. https://api.anthropic.com).
	// Unlike ExternalPrincipalExchange this is a FREE-FORM audience, not a
	// named scope profile, so it is validated strictly (see
	// validateFederationAudience) and the token carries NO ZeroID scopes.
	Audience string
	// TTLSeconds bounds the assertion lifetime. Clamped to [60, 3600]; default 900.
	TTLSeconds int
}

const (
	federationDefaultTTL = 900
	federationMinTTL     = 60
	federationMaxTTL     = 3600
)

// FederatedCredentialExchange mints a short-lived, provider-audienced assertion
// for the WIF broker path (ADR 0028 / CAP-IDN-023). It differs from
// ExternalPrincipalExchange in two security-sensitive ways, both compensated:
//
//   - It stamps a FREE-FORM provider audience, bypassing the audience-scope
//     profile gate. Compensating controls: (1) the trusted-service gate — only
//     an authenticated internal service (the AI gateway) can call this;
//     (2) the audience is validated as an absolute https URL with a public host
//     (no userinfo, no loopback/private IP); (3) the token is stamped
//     token_use=provider_federation, which the shared verifier (pkg/authjwt)
//     REJECTS for Highflame authentication, and carries NO ZeroID scopes — so a
//     leaked assertion cannot ride Highflame's own tenant-membership auth gates
//     and conveys zero ZeroID authority. It is usable ONLY as a bearer assertion
//     at the external provider whose federation rule accepts its (sub, aud, iss).
//   - It records an RFC 8693 `act.sub` = the AUTHENTICATED service name (never
//     a caller-supplied value), so the token is an honest delegation: `sub` is
//     the agent, `act.sub` is the broker. It is never impersonation — the
//     subject is never rewritten to the gateway.
//
// Trust boundary (audit round 1, accepted-and-documented):
//   - The caller asserts `SubjectWIMSE` and the tenant (account/project); ZeroID
//     does NOT re-verify the WIMSE against the identity store here (it mints for
//     a synthetic identity). So a compromised trusted service could mint an
//     assertion for an arbitrary agent WIMSE in an arbitrary tenant. The bound
//     is the PROVIDER's federation rule (subject_prefix / audience), which only
//     accepts subjects it recognizes — not ZeroID. A subject-belongs-to-tenant
//     lookup (mirroring ExternalPrincipalExchange's ApplicationID branch) is a
//     tracked hardening.
//   - `act.sub` is the trusted-service NAME authenticated by the shared internal
//     secret, so it identifies "a holder of the internal secret," not a specific
//     binary. Any trusted internal service can call this (same trust boundary as
//     the downstream-token routes); restricting the mint to the gateway service
//     is a tracked hardening.
//   - The free-form audience is validated (https, public host, no userinfo) but
//     NOT allowlisted to known providers; an allowlist is a tracked hardening,
//     lower priority now that the token_use marker makes a mis-audienced
//     assertion useless against Highflame's own services.
func (s *OAuthService) FederatedCredentialExchange(ctx context.Context, req FederatedExchangeRequest) (*domain.AccessToken, error) {
	// Step 1: Trusted-service gate. The broker (actor) identity is taken from
	// HERE, so a caller can never forge who brokered the assertion.
	if s.trustedServiceValidator == nil {
		return nil, oauthBadRequest(oautherror.InvalidGrant, "federated credential exchange is not configured")
	}
	brokerName, err := s.trustedServiceValidator(ctx)
	if err != nil {
		return nil, oauthBadRequestCause(oautherror.InvalidGrant, "caller is not a trusted service", err)
	}

	// Step 2: Validate shape. The trusted service authenticated the agent and
	// resolved the tenant; ZeroID validates the free-form audience strictly.
	if req.AccountID == "" || req.ProjectID == "" {
		return nil, oauthBadRequest(oautherror.InvalidRequest, "account_id and project_id are required")
	}
	if req.SubjectWIMSE == "" {
		return nil, oauthBadRequest(oautherror.InvalidRequest, "subject_wimse is required")
	}
	if err := validateFederationAudience(req.Audience); err != nil {
		return nil, oauthBadRequestCause(oautherror.InvalidTarget, "invalid federation audience", err)
	}

	// Step 3: Clamp the TTL to the federation window.
	ttl := federationDefaultTTL
	if req.TTLSeconds > 0 {
		ttl = min(max(req.TTLSeconds, federationMinTTL), federationMaxTTL)
	}

	// Step 4: Synthetic tenant-scoped identity. The subject is overridden to the
	// agent's WIMSE, so no identity row is required (mirrors
	// ExternalPrincipalExchange's no-ApplicationID path).
	identity := &domain.Identity{
		AccountID:    req.AccountID,
		ProjectID:    req.ProjectID,
		IdentityType: domain.IdentityTypeService,
		Status:       domain.IdentityStatusActive,
	}

	// Mark the assertion as federation-only so the shared verifier (pkg/authjwt)
	// refuses it for Highflame authentication — it is handed to an external
	// provider and must never ride Highflame's own tenant-membership auth gates
	// if it leaks (audit round 1).
	custom := map[string]any{"token_use": authjwt.TokenUseProviderFederation}
	if req.ExternalID != "" {
		custom["external_id"] = req.ExternalID
	}

	// Step 5: Issue. NO Scopes are set — the assertion conveys no ZeroID
	// authority; its only power is what the provider's federation rule grants.
	accessToken, _, err := s.credentialSvc.IssueCredential(ctx, IssueRequest{
		Identity:        identity,
		GrantType:       domain.GrantTypeTokenExchange,
		Audience:        []string{req.Audience},
		SubjectOverride: req.SubjectWIMSE,
		DelegatedBy:     brokerName,
		UseRS256:        true,
		TTL:             ttl,
		CustomClaims:    custom,
	})
	if err != nil {
		return nil, oauthServerError("failed to issue federated assertion", err)
	}

	accessToken.AccountID = req.AccountID
	accessToken.ProjectID = req.ProjectID
	return accessToken, nil
}

// validateFederationAudience enforces that a free-form provider audience is an
// absolute https URL with a host and no userinfo — mirroring the gateway-side
// endpoint hardening, and stopping the profile-gate bypass from stamping
// loopback / opaque / plaintext / userinfo-spoofed audiences.
func validateFederationAudience(aud string) error {
	u, err := url.Parse(aud)
	if err != nil {
		return fmt.Errorf("audience is not a valid URL: %w", err)
	}
	if u.Scheme != "https" {
		return errors.New("audience must be an https URL")
	}
	if u.Host == "" {
		return errors.New("audience must have a host")
	}
	if u.User != nil {
		return errors.New("audience must not contain userinfo")
	}
	// A real provider audience is a public host. Refuse loopback / private /
	// link-local literal IPs (audit round 1, H1) — they are never a legitimate
	// federation provider and only serve to point an assertion somewhere it
	// should not go.
	if ip := net.ParseIP(u.Hostname()); ip != nil && !isPublicIP(ip) {
		return errors.New("audience host must not be a loopback or private address")
	}
	return nil
}

// isPublicIP reports whether ip is a globally routable unicast address (not
// loopback, private, link-local, or unspecified).
func isPublicIP(ip net.IP) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast()
}
