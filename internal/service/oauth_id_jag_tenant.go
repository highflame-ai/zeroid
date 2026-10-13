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
// The two facts it is derived from, both known before the assertion is read:
//
//   - The account comes from the ISSUER's configuration. allowed_accounts is
//     the set of tenants this IdP may mint into; for a config-file issuer it is
//     the only binding between the IdP and a tenant.
//   - The account AND project come from the authenticated CLIENT's
//     registration. An oauth_clients row carries no tenant columns. Its tenant
//     is the identity its identity_id links to, a link an administrator writes
//     inside that identity's own tenant (the client-create handler refuses a
//     foreign identity_id). That identity is also D6's "identity the
//     credential maps to" for a registered client, whose subject key is the
//     client_id.
//
// The account must therefore be both the client's and one the issuer admits.
// The lookup is restricted to allowed_accounts in SQL, so the result is exactly
// one account or none; "none" is refused, never resolved by guessing.
//
// Fail closed on every gap:
//
//   - no allowed_accounts                     → invalid_grant (defence in depth;
//     config load already refuses it)
//   - client registration links no identity   → invalid_grant: there is no
//     project to derive, and with several allowed accounts no account either.
//     An issuer with a single allowed account still cannot supply a project.
//   - linked identity outside allowed_accounts → invalid_grant
//   - linked identity not active, or expired  → invalid_grant (ADR 0042 D7)
//
// account_id / project_id on the request are tolerated, not consulted: when
// present they MUST equal the derived values (D5), otherwise invalid_grant.
// They are never used to choose between candidates.
func deriveIDJAGTenant(
	ctx context.Context,
	issuer string,
	allowedAccounts []string,
	client *domain.OAuthClient,
	lookup linkedIdentityLookup,
	reqAccountID, reqProjectID string,
) (idJAGTenant, error) {
	// An empty allow-list admits no tenant. It is never read as "any".
	if len(allowedAccounts) == 0 {
		return idJAGTenant{}, oauthBadRequest(oautherror.InvalidGrant,
			fmt.Sprintf("issuer %s admits no accounts", issuer))
	}
	if client == nil || client.IdentityID == nil || *client.IdentityID == "" {
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

	derived := idJAGTenant{AccountID: linked.AccountID, ProjectID: linked.ProjectID}

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
