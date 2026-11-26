package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/oautherror"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// Internal service tokens are the tokens a deployment's own services present
// to each other. Each is bound to one receiver by an RFC 8707 resource and
// lives at most serviceTokenMaxTTL. A receiver identifies the calling service
// by claims only ZeroID writes, never by a scope or by aud:
//
//   - client_credentials into the service tenant: client_id together with the
//     service tenant's account_id.
//   - the on-behalf exchange (onBehalfExchange) and the asserted-tenant grant
//     (assertedTenantGrant): the outermost act.sub, the service identity's
//     WIMSE URI, together with act.client_id, the client the grant
//     authenticated.
//
// Everything here is off until ServiceTokenSettings names the service tenant.

// Values of the reserved claims internal service tokens carry.
const (
	// TenantSourceAsserted is tenant_source on an asserted-tenant token: the
	// calling service named the tenant.
	TenantSourceAsserted = "asserted"
	// SubjectKindPerson is subject_kind on an on-behalf token whose subject
	// was a person's own session; SubjectKindWorkload on every other.
	SubjectKindPerson   = "person"
	SubjectKindWorkload = "workload"
	// ResolvedUserSource values: the subject was the person
	// (ResolvedUserSourceSubject), a workload acting for the person
	// (ResolvedUserSourceOnBehalf), or a workload whose identity is owned by
	// the person (ResolvedUserSourceOwner).
	ResolvedUserSourceSubject  = "subject"
	ResolvedUserSourceOnBehalf = "on_behalf"
	ResolvedUserSourceOwner    = "owner"
)

// tokenExchangeOnBehalf is the token_exchange claim of an on-behalf token.
const tokenExchangeOnBehalf = "on_behalf"

// serviceTokenMaxTTL bounds every internal service token, in seconds.
const serviceTokenMaxTTL = 300

// ServiceTokenSettings configures internal service tokens. The zero value
// disables them. See the root package's ServiceTokensConfig for the meaning of
// each field.
type ServiceTokenSettings struct {
	AccountID             string
	ProjectID             string
	AssertedTenantClients []string
	SessionBrokerClients  []string
	ServedResources       map[string][]string
}

// serviceTokenConfig is the immutable form of ServiceTokenSettings that the
// grants read.
type serviceTokenConfig struct {
	accountID, projectID string
	asserted             map[string]bool
	brokers              map[string]bool
	served               map[string][]string
}

// SetServiceTokens installs the internal service token settings. An empty
// AccountID or ProjectID disables every internal service grant. Safe to call
// while requests are served.
func (s *OAuthService) SetServiceTokens(st ServiceTokenSettings) {
	if st.AccountID == "" || st.ProjectID == "" {
		s.serviceTokens.Store(nil)
		return
	}
	cfg := &serviceTokenConfig{
		accountID: st.AccountID,
		projectID: st.ProjectID,
		asserted:  make(map[string]bool, len(st.AssertedTenantClients)),
		brokers:   make(map[string]bool, len(st.SessionBrokerClients)),
		served:    make(map[string][]string, len(st.ServedResources)),
	}
	for _, id := range st.AssertedTenantClients {
		cfg.asserted[id] = true
	}
	for _, id := range st.SessionBrokerClients {
		cfg.brokers[id] = true
	}
	for id, resources := range st.ServedResources {
		cfg.served[id] = slices.Clone(resources)
	}
	s.serviceTokens.Store(cfg)
}

// SetAuditLogRepository wires the audit log the asserted-tenant grant writes
// to. Without it the grant refuses, since it must leave an audit row.
func (s *OAuthService) SetAuditLogRepository(repo *postgres.AuditLogRepository) {
	s.auditRepo = repo
}

// serviceTokenCfg returns the installed settings, or nil when internal service
// tokens are disabled.
func (s *OAuthService) serviceTokenCfg() *serviceTokenConfig {
	return s.serviceTokens.Load()
}

// inServiceTenant reports whether accountID is the service tenant's account.
// The whole account counts, not only its project: no tenant may hold any
// part of it.
func (c *serviceTokenConfig) inServiceTenant(accountID string) bool {
	return c != nil && accountID == c.accountID
}

// serves reports whether the service whose client is clientID serves
// resource: an entry ending in "/" covers every resource under it, any other
// entry only itself.
func (c *serviceTokenConfig) serves(clientID, resource string) bool {
	if c == nil {
		return false
	}
	for _, entry := range c.served[clientID] {
		if entry == resource || (strings.HasSuffix(entry, "/") && strings.HasPrefix(resource, entry)) {
			return true
		}
	}
	return false
}

// isSessionBrokerRequest reports whether req is a session broker's
// external-principal exchange: a client on SessionBrokerClients that names a
// person. Such a request authenticates as that client and nothing else.
func (s *OAuthService) isSessionBrokerRequest(req TokenRequest) bool {
	cfg := s.serviceTokenCfg()
	return cfg != nil && req.ClientID != "" && cfg.brokers[req.ClientID] && req.UserID != ""
}

// isOnBehalfCandidate reports whether a token exchange with no actor_token
// may be the on-behalf exchange: internal service tokens are on, the subject
// is an access token, and the request carries a private_key_jwt client
// assertion, the only way a service client authenticates. The exchange is
// taken only once that assertion verifies (see tokenExchange); a request
// that merely names a client_id keeps its old route.
func (s *OAuthService) isOnBehalfCandidate(req TokenRequest) bool {
	return s.serviceTokenCfg() != nil &&
		req.SubjectTokenType == TokenTypeAccessToken &&
		req.ClientID != "" &&
		clientAssertionPresented(req.ClientAssertion, req.ClientAssertionType)
}

// isReservedClientID reports whether id is reserved for the operator's own
// clients. False when no client service is wired.
func (s *OAuthService) isReservedClientID(id string) bool {
	return s.oauthClientSvc != nil && s.oauthClientSvc.IsReservedClientID(id)
}

// authenticateServiceClient authenticates the request's client and returns it
// with the service identity it is linked to. It refuses, as unauthorized for
// the grant, any client that is not one of the deployment's own services:
//
//   - it authenticates with private_key_jwt;
//   - its client id is reserved, so no tenant could have registered it;
//   - EnsureClient registered it (registration_source seed);
//   - it is linked to a usable service identity in the service tenant;
//   - when grantType is not empty, it lists grantType in its grant_types.
//
// Every condition is checked on every request, so suspending the service
// identity or deactivating the client stops the grant at once.
func (s *OAuthService) authenticateServiceClient(
	ctx context.Context, req TokenRequest, cfg *serviceTokenConfig, grantType string,
) (*domain.OAuthClient, *domain.Identity, error) {
	if req.ClientID == "" && !clientAssertionPresented(req.ClientAssertion, req.ClientAssertionType) {
		return nil, nil, oauthUnauthorized("this grant requires client authentication", nil)
	}
	// cimdFallback=false: a metadata-document client has no registration and
	// can never be one of the deployment's services.
	client, err := s.authenticateRegisteredClient(ctx, req, false)
	if err != nil {
		return nil, nil, err
	}
	identity, err := s.checkServiceClient(ctx, client, cfg, grantType)
	if err != nil {
		return nil, nil, err
	}
	return client, identity, nil
}

// checkServiceClient is authenticateServiceClient's check of a client that
// has already authenticated.
func (s *OAuthService) checkServiceClient(
	ctx context.Context, client *domain.OAuthClient, cfg *serviceTokenConfig, grantType string,
) (*domain.Identity, error) {
	identity, err := s.requireServiceClient(ctx, client, cfg)
	if err != nil {
		return nil, err
	}
	if grantType != "" && !slices.Contains(client.GrantTypes, grantType) {
		return nil, oauthBadRequest(oautherror.UnauthorizedClient, "client is not registered for this grant type")
	}
	return identity, nil
}

// requireServiceClient checks that an authenticated client is one of the
// deployment's own services (see authenticateServiceClient) and returns its
// service identity. The refusal does not say which check failed; the log does.
func (s *OAuthService) requireServiceClient(
	ctx context.Context, client *domain.OAuthClient, cfg *serviceTokenConfig,
) (*domain.Identity, error) {
	refuse := func(why string) (*domain.Identity, error) {
		log.Warn().Str("client_id", client.ClientID).Str("reason", why).
			Msg("refused an internal service grant: the client is not one of this deployment's services")
		return nil, oauthBadRequest(oautherror.UnauthorizedClient, "client is not authorized for this grant")
	}
	switch {
	case cfg == nil:
		return refuse("internal service tokens are not configured")
	case client.TokenEndpointAuthMethod != clientAuthMethodPrivateKeyJWT:
		return refuse("client does not authenticate with private_key_jwt")
	case !s.isReservedClientID(client.ClientID):
		return refuse("client id is not reserved")
	case client.RegistrationSource != domain.RegistrationSourceSeed:
		return refuse("client was not registered by seeding")
	case client.IdentityID == nil || *client.IdentityID == "":
		return refuse("client is not linked to an identity")
	}
	identity, err := s.identitySvc.repo.GetLinkedByID(ctx, *client.IdentityID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return refuse("client's identity no longer exists")
		}
		return nil, oauthServerError("failed to resolve the client's identity", err)
	}
	switch {
	case identity.AccountID != cfg.accountID || identity.ProjectID != cfg.projectID:
		return refuse("client's identity is not in the service tenant")
	case identity.IdentityType != domain.IdentityTypeService:
		return refuse("client's identity is not a service identity")
	case identity.WIMSEURI == "":
		return refuse("client's identity has no WIMSE URI")
	case !identity.Status.IsUsable():
		return nil, oauthBadRequest(oautherror.InvalidGrant, "service identity is suspended or deactivated")
	case identity.IsExpired():
		return nil, oauthBadRequest(oautherror.InvalidGrant, "identity_expired")
	}
	return identity, nil
}

// serviceActor is the outermost act of an internal service token: the
// service identity, and the client the grant authenticated.
func serviceActor(identity *domain.Identity, client *domain.OAuthClient) map[string]any {
	act := map[string]any{
		"sub":       identity.WIMSEURI,
		"client_id": client.ClientID,
	}
	if identity.IdentityType != "" {
		act["identity_type"] = string(identity.IdentityType)
	}
	if identity.TrustLevel != "" {
		act["trust_level"] = string(identity.TrustLevel)
	}
	if identity.ExternalID != "" {
		act["external_id"] = identity.ExternalID
	}
	return act
}

// actChain returns a token's act claim and each level's sub, outermost first.
// ok is false when act is present but is not a well-formed chain.
func actChain(tok jwt.Token) (act map[string]any, subs []string, ok bool) {
	if !tok.Has("act") {
		return nil, nil, true
	}
	act, err := jwt.Get[map[string]any](tok, "act")
	if err != nil {
		return nil, nil, false
	}
	for level := act; level != nil; {
		sub, _ := level["sub"].(string)
		subs = append(subs, sub)
		if len(subs) > domain.MaxActorChainDepth+1 {
			return nil, nil, false
		}
		next, present := level["act"]
		if !present {
			break
		}
		level, ok = next.(map[string]any)
		if !ok {
			return nil, nil, false
		}
	}
	return act, subs, true
}

// actHasClientID reports whether any level of an act chain carries client_id.
// Only the internal service grants write it.
func actHasClientID(act map[string]any) bool {
	for level := act; level != nil; {
		if _, ok := level["client_id"]; ok {
			return true
		}
		level, _ = level["act"].(map[string]any)
	}
	return false
}

// truncateActChain returns a copy of act keeping at most levels levels, the
// outermost first. RFC 8693 §4.1 lets an issuer drop prior actors, which are
// informational only.
func truncateActChain(act map[string]any, levels int) map[string]any {
	if act == nil || levels <= 0 {
		return nil
	}
	out := make(map[string]any, len(act))
	for k, v := range act {
		if k != "act" {
			out[k] = v
		}
	}
	if next, ok := act["act"].(map[string]any); ok {
		if nested := truncateActChain(next, levels-1); nested != nil {
			out["act"] = nested
		}
	}
	return out
}

// isInternalServiceToken reports whether a verified token is itself an
// internal service token, or is in the service tenant, which holds nothing
// else. Such a token is never a subject: exchanging one would let a tenant a
// service asserted, or a service's own authority, pass as a verified
// credential. It also refuses any token whose actor chain names an identity
// in the service tenant or carries act.client_id. cfg may be nil.
func isInternalServiceToken(tok jwt.Token, cred *domain.IssuedCredential, cfg *serviceTokenConfig, parseWIMSE func(string) (string, string, error)) bool {
	if cfg.inServiceTenant(cred.AccountID) {
		return true
	}
	if cred.GrantType == domain.GrantTypeAssertedTenant || tok.Has("tenant_source") {
		return true
	}
	if gt, _ := jwt.Get[string](tok, "grant_type"); gt == string(domain.GrantTypeAssertedTenant) {
		return true
	}
	if te, _ := jwt.Get[string](tok, "token_exchange"); te == tokenExchangeOnBehalf {
		return true
	}
	act, subs, ok := actChain(tok)
	if !ok {
		// An act ZeroID cannot read is not one it wrote; refuse it.
		return true
	}
	if actHasClientID(act) {
		return true
	}
	if cfg != nil {
		for _, sub := range subs {
			if account, _, err := parseWIMSE(sub); err == nil && cfg.inServiceTenant(account) {
				return true
			}
		}
	}
	return false
}

// personValue returns v when it can name a person: not empty and not a
// workload (SPIFFE/WIMSE) URI.
func personValue(v string) string {
	if strings.TrimSpace(v) == "" || isWorkloadURI(v) {
		return ""
	}
	return v
}

// isSessionBrokerToken reports whether an external-principal token was
// issued to a session broker that authenticated as itself: its client_id,
// which ZeroID writes only from the client the exchange authenticated, is on
// SessionBrokerClients and reserved. trusted_by alone is not enough: on the
// validator path it is the name the deployer's validator returned.
func (s *OAuthService) isSessionBrokerToken(tok jwt.Token, cfg *serviceTokenConfig) bool {
	cid, _ := jwt.Get[string](tok, "client_id")
	return cfg != nil && cid != "" && cfg.brokers[cid] && s.isReservedClientID(cid)
}

// isPersonSession reports whether a verified token is a person's own session,
// by the rules a resource server uses for person-only routes, never from sub
// alone (many workload-held tokens carry a person's sub):
//
//   - it names a person in sub and carries no external_id;
//   - it has no act and no resource binding, and its aud is only the issuer;
//   - its identity_type, when present, is not a workload type;
//   - it came from the external-principal exchange of a session broker, or
//     from the ID-token exchange, where ZeroID verified the person's IdP
//     token itself.
func (s *OAuthService) isPersonSession(tok jwt.Token, cfg *serviceTokenConfig) bool {
	sub, _ := tok.Subject()
	if personValue(sub) == "" || tok.Has("act") || tok.Has("resource") {
		return false
	}
	if ext, _ := jwt.Get[string](tok, "external_id"); ext != "" {
		return false
	}
	switch it, _ := jwt.Get[string](tok, "identity_type"); it {
	case "", string(domain.IdentityTypeService), "user", "human":
	default:
		return false
	}
	if gt, _ := jwt.Get[string](tok, "grant_type"); gt != string(domain.GrantTypeTokenExchange) {
		return false
	}
	switch te, _ := jwt.Get[string](tok, "token_exchange"); te {
	case "external_principal":
		if !s.isSessionBrokerToken(tok, cfg) {
			return false
		}
	case "external_id_token":
	default:
		return false
	}
	aud, _ := tok.Audience()
	for _, a := range aud {
		if a != s.issuer {
			return false
		}
	}
	return true
}

// resolveUser returns the user whose delegated credentials an on-behalf
// token's subject may use, and how it was resolved, from verified data only:
// the subject token's claims and its identity record. It never reads the
// request. A workload URI never qualifies at any step.
//
//  1. A person subject: the person. That is a person's own session, or, on a
//     token of the rfc8693 profile, a chain whose principal is a person,
//     whose sub is that person.
//  2. A legacy-profile workload acting for a person: the user_id claim, else,
//     at delegation_depth 1 or more, a non-workload act.sub.
//  3. Otherwise the owner on the subject's identity record. An API key's
//     creator is never consulted, and so neither is the owner of a service
//     identity reached through an API key: a key that names no identity is
//     minted on a shared placeholder service identity per product
//     (apiKeyOwnerOverride), whose recorded owner is whoever created its first
//     key, and a registered service identity cannot be told from it. Using
//     that owner would let one user's key spend another user's credentials.
//  4. Nothing: no user.
func resolveUser(tok jwt.Token, person bool, cred *domain.IssuedCredential, identity *domain.Identity) (string, string) {
	sub, _ := tok.Subject()
	if person {
		if p := personValue(sub); p != "" {
			return p, ResolvedUserSourceSubject
		}
	}
	if pt, err := jwt.Get[string](tok, "principal_type"); err == nil && pt != "" {
		if pt == string(domain.PrincipalUser) {
			if p := personValue(sub); p != "" {
				return p, ResolvedUserSourceSubject
			}
		}
	} else {
		if uid, _ := jwt.Get[string](tok, "user_id"); personValue(uid) != "" {
			return uid, ResolvedUserSourceOnBehalf
		}
		if delegationDepthOf(tok) >= 1 {
			if act, err := jwt.Get[map[string]any](tok, "act"); err == nil {
				if actSub, _ := act["sub"].(string); personValue(actSub) != "" {
					return actSub, ResolvedUserSourceOnBehalf
				}
			}
		}
	}
	placeholder := identity != nil && identity.IdentityType == domain.IdentityTypeService && cred.GrantType == domain.GrantTypeAPIKey
	if identity != nil && !placeholder {
		if owner := personValue(identity.OwnerUserID); owner != "" {
			return owner, ResolvedUserSourceOwner
		}
	}
	return "", ""
}

// tokenResources returns a verified token's reserved resource claim, whether
// it holds one value or several.
func tokenResources(tok jwt.Token) ([]string, bool) {
	if !tok.Has("resource") {
		return nil, true
	}
	v, err := jwt.Get[any](tok, "resource")
	if err != nil {
		return nil, false
	}
	switch r := v.(type) {
	case string:
		return []string{r}, true
	case []any:
		out := make([]string, 0, len(r))
		for _, e := range r {
			str, ok := e.(string)
			if !ok {
				return nil, false
			}
			out = append(out, str)
		}
		return out, true
	case []string:
		return r, true
	}
	return nil, false
}

// refuseServiceGrantParams refuses request parameters a grant does not take,
// so that nothing a caller sends can reach the token under another name. The
// internal service grants take their tenant, user and claims from verified
// data and configuration only.
func refuseServiceGrantParams(req TokenRequest, grant string, tenantAllowed bool) error {
	bad := func(param string) error {
		return oauthBadRequest(oautherror.InvalidRequest, fmt.Sprintf("%s is not accepted on the %s", param, grant))
	}
	switch {
	case !tenantAllowed && (req.AccountID != "" || req.ProjectID != ""):
		return bad("account_id / project_id")
	case req.UserID != "" || req.UserEmail != "" || req.UserName != "":
		return bad("user_id / user_email / user_name")
	case req.ApplicationID != "":
		return bad("application_id")
	case len(req.AdditionalClaims) > 0:
		return bad("additional_claims")
	case req.Role != "" || len(req.PrivilegeScope) > 0:
		return bad("role / privilege_scope")
	case req.Audience != "":
		return bad("audience")
	case req.IssueRefreshToken:
		return bad("issue_refresh_token")
	case req.Scope != "":
		return oauthBadRequest(oautherror.InvalidScope, fmt.Sprintf("the %s issues no scopes", grant))
	case len(req.Resource) != 1:
		return oauthBadRequest(oautherror.InvalidTarget, fmt.Sprintf("the %s requires exactly one resource", grant))
	}
	return nil
}

// onBehalfExchange is the on-behalf exchange (RFC 8693 with no actor_token):
// one of the deployment's services, authenticated as its own client,
// exchanges a token it received from a caller, and verified, for a token
// bound to the one receiver it is about to call, in the caller's tenant.
//
// ZeroID verifies the subject_token (signature, issuer, expiry, revocation),
// takes the tenant from the subject's credential row, adds the service as the
// outermost actor (act.sub, act.client_id) over the subject's own act chain,
// classifies the subject as a person's own session or a workload
// (subject_kind), resolves the user whose delegated credentials it may use
// (resolved_user_id, resolved_user_source), binds the token to the one
// requested resource, and sets exp to the earlier of five minutes and the
// subject's expiry. The token carries no scopes.
//
// It refuses: a client that is not one of the deployment's services; a
// subject that is itself an internal service token or in the service tenant;
// an external-principal subject not issued to a session broker; and a
// resource-bound subject unless the client serves every resource it is bound
// to.
//
// client is the client the request authenticated as; tokenExchange verified
// its assertion before routing here.
//
// The stricter scope rules' shadow count (token.scope_rules) records nothing
// here, on purpose: only the deployment's own services reach this exchange,
// a scope parameter is refused with invalid_scope and the token carries no
// scopes, so no client chooses a scope and every rule would answer as today
// does. It therefore never describes its request to the trace.
func (s *OAuthService) onBehalfExchange(ctx context.Context, req TokenRequest, client *domain.OAuthClient) (*domain.AccessToken, error) {
	cfg := s.serviceTokenCfg()
	if cfg == nil {
		return nil, oauthBadRequest(oautherror.UnsupportedGrantType, "the on-behalf exchange is not enabled")
	}
	if err := refuseServiceGrantParams(req, "on-behalf exchange", false); err != nil {
		return nil, err
	}
	svc, err := s.checkServiceClient(ctx, client, cfg, "urn:ietf:params:oauth:grant-type:token-exchange")
	if err != nil {
		return nil, err
	}

	// The subject: an active access token this server issued. Every refusal
	// below is invalid_grant with the same description; the log says which.
	refuse := func(why string) error {
		log.Warn().Str("client_id", client.ClientID).Str("reason", why).Msg("on-behalf exchange refused its subject_token")
		return oauthBadRequest(oautherror.InvalidGrant, "subject_token cannot be exchanged on behalf")
	}
	tok, err := s.parseToken(req.SubjectToken, true)
	if err != nil {
		return nil, refuse("not a valid, unexpired token from this issuer")
	}
	if iss, _ := tok.Issuer(); iss != s.issuer {
		return nil, refuse("not issued by this server")
	}
	jti, _ := tok.JwtID()
	if jti == "" {
		return nil, refuse("no jti")
	}
	cred, active, err := s.credentialSvc.IntrospectToken(ctx, jti)
	if err != nil {
		return nil, oauthServerError("failed to check subject_token", err)
	}
	if cred == nil || !active {
		return nil, refuse("inactive or revoked")
	}
	if cred.AccountID == "" || cred.ProjectID == "" {
		return nil, refuse("no complete tenant")
	}
	if isInternalServiceToken(tok, cred, cfg, s.parseWIMSEURI) {
		return nil, refuse("an internal service token, or a token in the service tenant")
	}
	te, _ := jwt.Get[string](tok, "token_exchange")
	if te == "external_principal" && !s.isSessionBrokerToken(tok, cfg) {
		return nil, refuse("an external-principal token not issued to a session broker")
	}
	if cid, _ := jwt.Get[string](tok, "client_id"); cid != "" && s.isReservedClientID(cid) &&
		(te != "external_principal" || !cfg.brokers[cid]) {
		return nil, refuse("issued to one of this deployment's own clients")
	}
	resources, ok := tokenResources(tok)
	if !ok {
		return nil, refuse("malformed resource claim")
	}
	for _, r := range resources {
		if !cfg.serves(client.ClientID, r) {
			return nil, refuse("bound to a resource this client does not serve")
		}
	}

	// The subject's identity, when it has one, must still be usable: an
	// exchange must not outlive a suspension the subject's own token
	// introspection would already report.
	var subjectIdentity *domain.Identity
	if cred.IdentityID != nil && *cred.IdentityID != "" {
		subjectIdentity, err = s.identitySvc.repo.GetByID(ctx, *cred.IdentityID, cred.AccountID, cred.ProjectID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, refuse("subject identity no longer exists")
			}
			return nil, oauthServerError("failed to resolve the subject's identity", err)
		}
		if !subjectIdentity.Status.IsUsable() || subjectIdentity.IsExpired() {
			return nil, refuse("subject identity is not usable")
		}
	}
	carrier := subjectIdentity
	if carrier == nil {
		// No identity row (a person's session): a carrier for the tenant, as
		// the external-principal exchange mints on.
		carrier = &domain.Identity{
			AccountID:    cred.AccountID,
			ProjectID:    cred.ProjectID,
			IdentityType: domain.IdentityTypeService,
			Status:       domain.IdentityStatusActive,
		}
	}

	person := s.isPersonSession(tok, cfg)
	kind := SubjectKindWorkload
	if person {
		kind = SubjectKindPerson
	}
	resolvedUser, resolvedSource := resolveUser(tok, person, cred, subjectIdentity)

	act := serviceActor(svc, client)
	subjectAct, _, _ := actChain(tok)
	if nested := truncateActChain(subjectAct, domain.MaxActorChainDepth-1); nested != nil {
		act["act"] = nested
	}

	missionID, _ := jwt.Get[string](tok, "mission_id")
	if missionID == "" {
		missionID = jti
	}
	sub, _ := tok.Subject()
	delegatedBy := sub
	if prior := priorActorsOf(tok); len(prior) > 0 {
		delegatedBy = prior[0].Sub
	}
	principal := s.parentPrincipal(tok, cred, delegationDepthOf(tok))
	expiresAt := cred.ExpiresAt

	issue := IssueRequest{
		Identity:            carrier,
		GrantType:           domain.GrantTypeTokenExchange,
		TTL:                 serviceTokenMaxTTL,
		CredentialExpiresAt: &expiresAt,
		SubjectOverride:     sub,
		PrincipalType:       principal.Type,
		PrincipalSub:        principal.Sub,
		PrincipalIss:        principal.Iss,
		ParentJTI:           jti,
		DelegatedBy:         delegatedBy,
		DelegationDepth:     delegationDepthOf(tok) + 1,
		MissionID:           missionID,
		ClientID:            client.ClientID,
		DPoPKeyThumbprint:   req.DPoPKeyThumbprint,
		ServiceAct:          act,
		SubjectKind:         kind,
		ResolvedUserID:      resolvedUser,
		ResolvedUserSource:  resolvedSource,
		CustomClaims:        map[string]any{"token_exchange": tokenExchangeOnBehalf},
	}
	bindResourceOnIssue(&issue, req.Resource)

	accessToken, _, err := s.credentialSvc.IssueCredential(ctx, issue)
	if err != nil {
		if issuanceRefusal(err) {
			return nil, err
		}
		return nil, oauthServerError("failed to issue on-behalf token", err)
	}
	accessToken.AccountID = cred.AccountID
	accessToken.ProjectID = cred.ProjectID
	return accessToken, nil
}

// assertedTenantGrant is the asserted-tenant grant: one of the deployment's
// services, on AssertedTenantClients and authenticated as its own client,
// names a tenant (account_id, project_id) and receives a token for it, bound
// to one receiver, for background work with no caller to act for. The token
// carries tenant_source=asserted, the service as its actor (act.sub,
// act.client_id) and principal, no scopes, and lives five minutes. Every
// issuance writes an audit row in the named tenant, and the token is revoked
// if the row cannot be written.
//
// The stricter scope rules' shadow count does not evaluate this grant (see
// scopeTraceGrant): only the deployment's own services reach it, a scope
// parameter is refused with invalid_scope and the token carries no scopes.
func (s *OAuthService) assertedTenantGrant(ctx context.Context, req TokenRequest) (*domain.AccessToken, error) {
	cfg := s.serviceTokenCfg()
	if cfg == nil || len(cfg.asserted) == 0 {
		return nil, oauthBadRequest(oautherror.UnsupportedGrantType, "the asserted-tenant grant is not enabled")
	}
	if err := refuseServiceGrantParams(req, "asserted-tenant grant", true); err != nil {
		return nil, err
	}
	if req.SubjectToken != "" || req.ActorToken != "" {
		return nil, oauthBadRequest(oautherror.InvalidRequest, "subject_token and actor_token are not accepted on the asserted-tenant grant")
	}
	if req.AccountID == "" || req.ProjectID == "" {
		return nil, oauthBadRequest(oautherror.InvalidRequest, "account_id and project_id are required for the asserted-tenant grant")
	}
	client, svc, err := s.authenticateServiceClient(ctx, req, cfg, domain.GrantTypeAssertedTenantURN)
	if err != nil {
		return nil, err
	}
	if !cfg.asserted[client.ClientID] {
		log.Warn().Str("client_id", client.ClientID).Msg("refused the asserted-tenant grant: the client is not on service_tokens.asserted_tenant_clients")
		return nil, oauthBadRequest(oautherror.UnauthorizedClient, "client is not authorized for this grant")
	}
	if cfg.inServiceTenant(req.AccountID) {
		return nil, oauthBadRequest(oautherror.InvalidRequest, "the service tenant cannot be asserted")
	}
	if s.auditRepo == nil {
		return nil, oauthServerError("the asserted-tenant grant has no audit log configured", nil)
	}

	carrier := &domain.Identity{
		AccountID:    req.AccountID,
		ProjectID:    req.ProjectID,
		WIMSEURI:     svc.WIMSEURI,
		IdentityType: domain.IdentityTypeService,
		Status:       domain.IdentityStatusActive,
	}
	issue := IssueRequest{
		Identity:          carrier,
		GrantType:         domain.GrantTypeAssertedTenant,
		TTL:               serviceTokenMaxTTL,
		PrincipalType:     domain.PrincipalWorkload,
		PrincipalSub:      svc.WIMSEURI,
		PrincipalIss:      s.issuer,
		ClientID:          client.ClientID,
		DPoPKeyThumbprint: req.DPoPKeyThumbprint,
		ServiceAct:        serviceActor(svc, client),
		TenantSource:      TenantSourceAsserted,
	}
	bindResourceOnIssue(&issue, req.Resource)

	accessToken, cred, err := s.credentialSvc.IssueCredential(ctx, issue)
	if err != nil {
		if issuanceRefusal(err) {
			return nil, err
		}
		return nil, oauthServerError("failed to issue asserted-tenant token", err)
	}
	if err := s.auditAssertedTenant(ctx, cred, client, svc, req.Resource[0]); err != nil {
		// Fail closed: an asserted tenant must leave a trace. The token was
		// never returned, but its row exists, so revoke it.
		if rerr := s.credentialSvc.RevokeCredential(ctx, cred.ID, cred.AccountID, cred.ProjectID, "asserted_tenant_audit_failed"); rerr != nil {
			log.Error().Err(rerr).Str("jti", cred.JTI).Msg("failed to revoke an asserted-tenant token whose audit row could not be written")
		}
		return nil, oauthServerError("failed to audit the asserted-tenant grant", err)
	}
	log.Info().Str("client_id", client.ClientID).Str("account_id", req.AccountID).Str("project_id", req.ProjectID).
		Str("resource", req.Resource[0]).Str("jti", cred.JTI).Msg("issued an asserted-tenant token")
	accessToken.AccountID = req.AccountID
	accessToken.ProjectID = req.ProjectID
	return accessToken, nil
}

// auditActionAssertTenant is the identity_audit_logs action of an
// asserted-tenant issuance.
const auditActionAssertTenant = "ASSERT_TENANT"

// auditAssertedTenant writes the audit row of an asserted-tenant issuance, in
// the asserted tenant, naming the client as the caller.
func (s *OAuthService) auditAssertedTenant(
	ctx context.Context, cred *domain.IssuedCredential, client *domain.OAuthClient, svc *domain.Identity, resource string,
) error {
	data, err := json.Marshal(map[string]any{
		"jti":                 cred.JTI,
		"client_id":           client.ClientID,
		"service_identity_id": svc.ID,
		"actor":               svc.WIMSEURI,
		"resource":            resource,
		"expires_at":          cred.ExpiresAt.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	return s.auditRepo.Insert(ctx, &postgres.AuditLogEntry{
		ID:        uuid.New().String(),
		AccountID: cred.AccountID,
		ProjectID: cred.ProjectID,
		TableName: "issued_credentials",
		Action:    auditActionAssertTenant,
		Status:    "SUCCESS",
		UserID:    client.ClientID,
		NewData:   data,
		CreatedAt: time.Now().UTC(),
	})
}
