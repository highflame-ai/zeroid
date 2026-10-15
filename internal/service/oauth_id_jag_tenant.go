package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/oautherror"
)

// idJAGTenant is the Highflame tenant an ID-JAG redemption mints into.
type idJAGTenant struct {
	AccountID string
	ProjectID string
}

// linkedIdentityLookup loads the identity an OAuth client's registration links
// to, restricted to accountIDs. It must return an error wrapping sql.ErrNoRows
// when no such identity exists inside those accounts.
type linkedIdentityLookup func(ctx context.Context, identityID string, accountIDs []string) (*domain.Identity, error)

// deriveIDJAGTenant decides which tenant an ID-JAG redemption mints into. The
// tenant is DERIVED from server-side facts; the request never chooses it
// (ADR 0042 D5, amending ADR 0010 D3).
//
// Why the request cannot supply it. The ID-JAG profile defines the access token
// request as grant_type, assertion and client authentication "as registered
// with the Resource Authorization Server" (draft-ietf-oauth-identity-assertion-
// authz-grant-04 §4.4; MCP Enterprise-Managed Authorization §5). No conformant
// client sends a Highflame account or project, and none has a way to learn one.
// It also must not: the caller is the agent, so a caller-chosen tenant lets the
// agent pick whose tenant its token lands in.
//
// The facts it is derived from, all known before the assertion is read:
//
//   - The account comes from the ISSUER's configuration. allowed_accounts is
//     the set of tenants this IdP may mint into; for a config-file issuer it is
//     the only binding between the IdP and a tenant.
//   - For a REGISTERED client, the account AND project come from its
//     registration. An oauth_clients row carries no tenant columns. Its tenant
//     is the identity its identity_id links to, a link an administrator writes
//     inside that identity's own tenant (the client-create handler refuses a
//     foreign identity_id). That identity is also D6's "identity the
//     credential maps to" for a registered client, whose subject key is the
//     client_id. The lookup is restricted to allowed_accounts in SQL, so the
//     result is exactly one account or none.
//   - For a CIMD client (no registration, so no tenant of its own), the
//     tenant would come from the identity its client_id is bound to (ADR 0042
//     D6). That binding does not exist yet, so a CIMD client is refused; see
//     cimdClientTenant.
//
// Fail closed on every gap:
//
//   - no allowed_accounts                     → invalid_grant (defence in depth;
//     config load already refuses it)
//   - registered client links no identity     → invalid_grant: there is no
//     project to derive, and with several allowed accounts no account either.
//     An issuer with a single allowed account still cannot supply a project.
//   - linked identity outside allowed_accounts → invalid_grant
//   - linked identity not active, or expired  → invalid_grant (ADR 0042 D7)
//   - CIMD client (no D6 binding exists yet)  → invalid_grant
//
// account_id / project_id on the request are tolerated, not consulted: when
// present they MUST equal the derived values (D5), otherwise invalid_grant.
// They are never used to choose between candidates.
func deriveIDJAGTenant(
	ctx context.Context,
	cfg *domain.ExternalIssuerConfig,
	client *domain.OAuthClient,
	lookup linkedIdentityLookup,
	reqAccountID, reqProjectID string,
) (idJAGTenant, error) {
	// An empty allow-list admits no tenant. It is never read as "any".
	if cfg == nil || len(cfg.AllowedAccounts) == 0 {
		issuer := ""
		if cfg != nil {
			issuer = cfg.Issuer
		}
		return idJAGTenant{}, oauthBadRequest(oautherror.InvalidGrant,
			fmt.Sprintf("issuer %s admits no accounts", issuer))
	}
	if client == nil {
		return idJAGTenant{}, oauthBadRequest(oautherror.InvalidGrant, "no authenticated client to derive a tenant from")
	}

	var (
		derived idJAGTenant
		err     error
	)
	if client.SelfAsserted() {
		derived, err = cimdClientTenant(cfg, client)
	} else {
		derived, err = registeredClientTenant(ctx, cfg, client, lookup)
	}
	if err != nil {
		return idJAGTenant{}, err
	}

	// ADR 0042 D5: a request that also names a tenant must name THIS one. The
	// messages do not echo the derived values; the caller either already knows
	// them or has no business learning them from an error.
	if reqAccountID != "" && reqAccountID != derived.AccountID {
		return idJAGTenant{}, oauthBadRequest(oautherror.InvalidGrant,
			"account_id does not match the tenant derived for this client and issuer")
	}
	if reqProjectID != "" && reqProjectID != derived.ProjectID {
		return idJAGTenant{}, oauthBadRequest(oautherror.InvalidGrant,
			"project_id does not match the tenant derived for this client and issuer")
	}
	return derived, nil
}

// cimdClientTenant would read a CIMD client's tenant from a static issuer,
// which has no bindings, so it always refuses. Issuer rows bind the agent
// through act.sub instead (bindFederatedAgent), which serves a CIMD client.
//
// ADR 0042 D5 takes the project for this path from "the identity the
// credential maps to", and D6 says a CIMD client's credential maps to an
// identity through a binding keyed on its client_id. That binding does not
// exist yet: a CIMD client has no oauth_clients row, so no identity_id link,
// and an identity's external_id cannot hold a URL (it must be a SPIFFE path
// segment). None of the remaining candidates is acceptable. The request's
// account_id/project_id may only be checked against a derived tenant, never
// choose one. A single allowed_accounts entry names an account but no
// project, and taking either from it alone would let any document publisher
// mint into a tenant it never had to be admitted to.
//
// So this is the seam where the D6 binding plugs in: look up the enabled
// (issuer, client_id) → identity binding, read the tenant from that identity
// (inside allowed_accounts, active only, D7), and return it. Until then a CIMD
// client gets as far as authenticating with its document's key and passing the
// client_id binding, then stops here with invalid_grant.
func cimdClientTenant(cfg *domain.ExternalIssuerConfig, _ *domain.OAuthClient) (idJAGTenant, error) {
	return idJAGTenant{}, oauthBadRequest(oautherror.InvalidGrant, fmt.Sprintf(
		"no binding maps this client metadata document client to an identity in an account issuer %s "+
			"may mint into, so the ID-JAG cannot be bound to a tenant", cfg.Issuer))
}

// registeredClientTenant reads a registered client's tenant from the identity
// its registration links to, restricted to the issuer's allowed_accounts.
func registeredClientTenant(
	ctx context.Context,
	cfg *domain.ExternalIssuerConfig,
	client *domain.OAuthClient,
	lookup linkedIdentityLookup,
) (idJAGTenant, error) {
	issuer, allowedAccounts := cfg.Issuer, cfg.AllowedAccounts
	if client.IdentityID == nil || *client.IdentityID == "" {
		return idJAGTenant{}, oauthBadRequest(oautherror.InvalidGrant,
			"the authenticated client is not registered to a tenant (it links no identity), "+
				"so the ID-JAG cannot be bound to one; the tenant is derived from the client's "+
				"registration and the issuer, never taken from the request")
	}

	linked, err := lookup(ctx, *client.IdentityID, allowedAccounts)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Either the link dangles or it points into a tenant this issuer does
			// not admit. The lookup cannot tell them apart by design, and both
			// mean the same thing here: no admitted tenant for this client.
			return idJAGTenant{}, oauthBadRequestCause(oautherror.InvalidGrant,
				fmt.Sprintf("the authenticated client's tenant is not one issuer %s may mint into", issuer), err)
		}
		return idJAGTenant{}, oauthServerError("failed to resolve the client's registered tenant", err)
	}

	// Re-checked here rather than trusted from the lookup's WHERE clause: this
	// is the tenant-admission decision, and it should not rest on one query
	// predicate one file away.
	if !slices.Contains(allowedAccounts, linked.AccountID) {
		return idJAGTenant{}, oauthBadRequest(oautherror.InvalidGrant,
			fmt.Sprintf("the authenticated client's tenant is not one issuer %s may mint into", issuer))
	}
	if linked.AccountID == "" || linked.ProjectID == "" {
		return idJAGTenant{}, oauthBadRequest(oautherror.InvalidGrant,
			"the authenticated client's registered identity has no complete tenant")
	}
	// ADR 0042 D7 and the same gate authorization_code applies to a linked
	// client: a suspended, deactivated or expired identity mints nothing.
	if !linked.Status.IsUsable() {
		return idJAGTenant{}, oauthBadRequest(oautherror.InvalidGrant, "identity is suspended or deactivated")
	}
	if linked.IsExpired() {
		return idJAGTenant{}, oauthBadRequest(oautherror.InvalidGrant, "identity_expired")
	}
	return idJAGTenant{AccountID: linked.AccountID, ProjectID: linked.ProjectID}, nil
}
