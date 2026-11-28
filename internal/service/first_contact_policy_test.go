package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// An adopt row's first_contact_credential_policy_id: the credential policy it
// assigns to every agent it adopts (docs/external-issuers.md, "First
// contact"). These cover what needs no database; tests/integration covers the
// rest against Postgres.

const (
	fcPolicyID    = "11111111-2222-4333-8444-555555555555"
	fcOtherPolicy = "66666666-7777-4888-9999-aaaaaaaaaaaa"
)

// fakePolicies is a credential policy store keyed by (account, project, id).
// It records every read, and whether it was share-locked.
type fakePolicies struct {
	policies map[string]*domain.CredentialPolicy
	err      error
	reads    []string
}

func (f *fakePolicies) key(id, accountID, projectID string) string {
	return accountID + "|" + projectID + "|" + id
}

func (f *fakePolicies) read(kind, id, accountID, projectID string) (*domain.CredentialPolicy, error) {
	f.reads = append(f.reads, kind+" "+f.key(id, accountID, projectID))
	if f.err != nil {
		return nil, f.err
	}
	p, ok := f.policies[f.key(id, accountID, projectID)]
	if !ok {
		return nil, fmt.Errorf("failed to get credential policy: %w", sql.ErrNoRows)
	}
	c := *p
	return &c, nil
}

func (f *fakePolicies) GetByID(_ context.Context, id, accountID, projectID string) (*domain.CredentialPolicy, error) {
	return f.read("get", id, accountID, projectID)
}

func (f *fakePolicies) GetByIDForShare(_ context.Context, id, accountID, projectID string) (*domain.CredentialPolicy, error) {
	return f.read("share", id, accountID, projectID)
}

func fcPolicy(id string) *domain.CredentialPolicy {
	return &domain.CredentialPolicy{ID: id, Name: "workloads", IsActive: true, AllowedScopes: []string{"tools:read"},
		AllowedGrantTypes: []string{"client_credentials"}}
}

// policyStore holds one usable policy, fcPolicyID, in acct-a/proj-fc, and
// lets a test change it.
func policyStore(mutate func(*domain.CredentialPolicy)) *fakePolicies {
	p := fcPolicy(fcPolicyID)
	if mutate != nil {
		mutate(p)
	}
	f := &fakePolicies{policies: map[string]*domain.CredentialPolicy{}}
	f.policies[f.key(fcPolicyID, "acct-a", "proj-fc")] = p
	return f
}

func adoptRow(policy string) *domain.ExternalIssuer {
	return &domain.ExternalIssuer{ID: "row-1", AccountID: "acct-a", Issuer: "https://idp.example", Enabled: true,
		FirstContact: domain.FirstContactAdopt, FirstContactProjectID: "proj-fc", FirstContactOwnerUserID: "owner",
		FirstContactCredentialPolicyID: policy, FirstContactUpdatedBy: "user-admin"}
}

func TestFirstContactPolicyProblem(t *testing.T) {
	past, future := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	for name, tc := range map[string]struct {
		mutate func(*domain.CredentialPolicy)
		want   string
	}{
		"active, no expiry":       {func(*domain.CredentialPolicy) {}, ""},
		"expires later":           {func(p *domain.CredentialPolicy) { p.ExpiresAt = &future }, ""},
		"inactive":                {func(p *domain.CredentialPolicy) { p.IsActive = false }, "is inactive"},
		"expired":                 {func(p *domain.CredentialPolicy) { p.ExpiresAt = &past }, "has expired"},
		"lists ciba:approve":      {func(p *domain.CredentialPolicy) { p.AllowedScopes = append(p.AllowedScopes, domain.ScopeCIBAApprove) }, "ciba:approve"},
		"no scope ceiling at all": {func(p *domain.CredentialPolicy) { p.AllowedScopes = nil }, ""},
	} {
		t.Run(name, func(t *testing.T) {
			p := fcPolicy(fcPolicyID)
			tc.mutate(p)
			got := firstContactPolicyProblem(p)
			if tc.want == "" {
				assert.Empty(t, got)
				return
			}
			assert.Contains(t, got, tc.want)
		})
	}
}

// Adoption time: a policy that is missing or cannot be assigned declines the
// attempt (nothing is written, the grant refuses as without first contact);
// only a failed read is an error.
func TestFirstContactPolicyDeclines(t *testing.T) {
	ctx := context.Background()
	past := time.Now().Add(-time.Minute)

	t.Run("a row that names no policy never reads one", func(t *testing.T) {
		store := policyStore(nil)
		res, err := (&FirstContactRegistrar{policies: store}).policyDeclines(ctx, adoptRow(""))
		require.NoError(t, err)
		assert.Empty(t, res.outcome)
		assert.Empty(t, store.reads)
	})

	t.Run("a usable policy in the row's account and project: no decline", func(t *testing.T) {
		store := policyStore(nil)
		res, err := (&FirstContactRegistrar{policies: store}).policyDeclines(ctx, adoptRow(fcPolicyID))
		require.NoError(t, err)
		assert.Empty(t, res.outcome)
		assert.Equal(t, []string{"get acct-a|proj-fc|" + fcPolicyID}, store.reads, "read in the mapped tenant, unlocked")
	})

	for name, tc := range map[string]struct {
		store *fakePolicies
		row   *domain.ExternalIssuer
		reads bool
	}{
		"missing (deleted, or in another project)": {policyStore(nil), adoptRow(fcOtherPolicy), true},
		"inactive":                       {policyStore(func(p *domain.CredentialPolicy) { p.IsActive = false }), adoptRow(fcPolicyID), true},
		"expired":                        {policyStore(func(p *domain.CredentialPolicy) { p.ExpiresAt = &past }), adoptRow(fcPolicyID), true},
		"lists ciba:approve":             {policyStore(func(p *domain.CredentialPolicy) { p.AllowedScopes = []string{domain.ScopeCIBAApprove} }), adoptRow(fcPolicyID), true},
		"not a policy id at all":         {policyStore(nil), adoptRow("not-a-uuid"), false},
		"the row's project has moved on": {policyStore(nil), func() *domain.ExternalIssuer { r := adoptRow(fcPolicyID); r.FirstContactProjectID = "proj-2"; return r }(), true},
	} {
		t.Run("fails closed: "+name, func(t *testing.T) {
			res, err := (&FirstContactRegistrar{policies: tc.store}).policyDeclines(ctx, tc.row)
			require.NoError(t, err)
			assert.Equal(t, firstContactPolicyUnusable, res.outcome)
			assert.Equal(t, tc.row.FirstContactCredentialPolicyID, res.policy, "the policy the decision read is logged")
			assert.False(t, res.outcome.rereads(), "the grant refuses as without first contact")
			assert.Equal(t, tc.reads, len(tc.store.reads) > 0)
		})
	}

	t.Run("a failed read is an error, not a decline", func(t *testing.T) {
		store := policyStore(nil)
		store.err = errors.New("connection reset")
		_, err := (&FirstContactRegistrar{policies: store}).policyDeclines(ctx, adoptRow(fcPolicyID))
		require.Error(t, err)
	})

	t.Run("no policy store with a policy to read is an error", func(t *testing.T) {
		_, err := (&FirstContactRegistrar{}).policyDeclines(ctx, adoptRow(fcPolicyID))
		require.Error(t, err)
	})
}

// A registration under adopt assigns the row's policy as the identity's own;
// with none named, RegisterIdentity assigns the project's default as before.
func TestFirstContactRegistration(t *testing.T) {
	labels, metadata := json.RawMessage(`{"l":"1"}`), json.RawMessage(`{"m":1}`)
	a := firstContactArrival{row: adoptRow(fcPolicyID), subjectKey: "system:serviceaccount:agents:planner", grant: federatedGrantClientCredentials}

	t.Run("adopt with a policy", func(t *testing.T) {
		req := firstContactRegistration(a, adoptRow(fcPolicyID), "first_contact.x", labels, metadata)
		assert.Equal(t, fcPolicyID, req.CredentialPolicyID, "the row's policy is the identity's own")
		assert.True(t, req.adopted)
		assert.True(t, req.firstContact)
		assert.Equal(t, domain.TrustLevelVerifiedThirdParty, req.TrustLevel)
		assert.Equal(t, "acct-a", req.AccountID)
		assert.Equal(t, "proj-fc", req.ProjectID)
		assert.Equal(t, "owner", req.OwnerUserID)
		assert.Equal(t, "first_contact.x", req.ExternalID)
		assert.Equal(t, domain.OriginFirstContact, req.Origin)
		assert.Equal(t, FirstContactActor, req.CreatedBy)
		assert.Equal(t, labels, req.Labels)
		assert.Equal(t, metadata, req.Metadata)
	})

	t.Run("adopt without one: the project's default, assigned by RegisterIdentity", func(t *testing.T) {
		req := firstContactRegistration(a, adoptRow(""), "first_contact.x", labels, metadata)
		assert.Empty(t, req.CredentialPolicyID)
		assert.True(t, req.adopted)
	})

	t.Run("discover assigns nothing and adopts nothing", func(t *testing.T) {
		row := adoptRow(fcPolicyID) // as a database CHECK makes impossible: shows discover never reads it
		row.FirstContact = domain.FirstContactDiscover
		req := firstContactRegistration(a, row, "first_contact.x", labels, metadata)
		assert.Empty(t, req.CredentialPolicyID)
		assert.False(t, req.adopted)
		assert.Equal(t, domain.TrustLevelUnverified, req.TrustLevel)
	})
}

// A standing adoption assigns the row's policy as the identity's own,
// replacing what it had; with none named it keeps its own, or takes the
// project's default when it has none.
func TestStandingAdoptionUpdate(t *testing.T) {
	labels, metadata := json.RawMessage(`{"l":"1"}`), json.RawMessage(`{"m":1}`)
	withPolicy := func(p string) *domain.Identity {
		return &domain.Identity{ID: "id-1", AccountID: "acct-a", ProjectID: "proj-fc", Status: domain.IdentityStatusDiscovered, CredentialPolicyID: p}
	}
	const projectDefault = "99999999-0000-4000-8000-000000000000"

	for name, tc := range map[string]struct {
		row      string
		identity string
		want     *string
	}{
		"the row's policy replaces the project default the agent was born with": {fcPolicyID, projectDefault, ptr(fcPolicyID)},
		"the row's policy replaces a policy of its own":                         {fcPolicyID, fcOtherPolicy, ptr(fcPolicyID)},
		"the row's policy on an agent with none":                                {fcPolicyID, "", ptr(fcPolicyID)},
		"no row policy: the agent keeps its own":                                {"", fcOtherPolicy, nil},
		"no row policy and none of its own: the project's default":              {"", "", ptr("")},
	} {
		t.Run(name, func(t *testing.T) {
			update := standingAdoptionUpdate(withPolicy(tc.identity), adoptRow(tc.row), labels, metadata)
			if tc.want == nil {
				assert.Nil(t, update.CredentialPolicyID)
			} else {
				require.NotNil(t, update.CredentialPolicyID)
				assert.Equal(t, *tc.want, *update.CredentialPolicyID)
			}
			require.NotNil(t, update.Status)
			assert.Equal(t, domain.IdentityStatusActive, *update.Status)
			assert.Equal(t, "owner", update.OwnerUserID)
			assert.Equal(t, domain.TrustLevelVerifiedThirdParty, update.TrustLevel)
			assert.Equal(t, labels, update.Labels)
			assert.Equal(t, metadata, update.Metadata)
		})
	}
}

func ptr(s string) *string { return &s }

// The adoption record names the policy the mapping assigned, so an identity's
// audit trail says which policy adopted it even after the row changes.
func TestFirstContactMarkers_Policy(t *testing.T) {
	row := adoptRow(fcPolicyID)
	a := firstContactArrival{row: row, subjectKey: "sa", grant: federatedGrantClientCredentials}
	_, metadata, err := firstContactMarkers(a, row)
	require.NoError(t, err)
	var m map[string]map[string]any
	require.NoError(t, json.Unmarshal(metadata, &m))
	assert.Equal(t, fcPolicyID, m["first_contact_adoption"]["credential_policy_id"])

	_, standing, err := standingAdoptionMarkers(&domain.Identity{}, a, row)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(standing, &m))
	assert.Equal(t, fcPolicyID, m["first_contact_adoption"]["credential_policy_id"])

	_, none, err := standingAdoptionMarkers(&domain.Identity{}, a, adoptRow(""))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(none, &m))
	assert.NotContains(t, m["first_contact_adoption"], "credential_policy_id", "no policy named: none recorded")
}

// The ID-JAG grant's decline before the lock: the step writes nothing and
// does not read the bindings again, so bindAgent refuses as without first
// contact.
func TestFirstContactFor_PolicyDecline(t *testing.T) {
	s := &OAuthService{firstContact: &FirstContactRegistrar{}}
	step := s.firstContactFor(adoptRow(fcPolicyID), "0oa-agent", federatedGrantIDJAG, nil, func(context.Context) (firstContactOutcome, error) {
		return firstContactPolicyUnusable, nil
	})
	require.NotNil(t, step)
	reread, err := step(context.Background(), nil)
	require.NoError(t, err)
	assert.False(t, reread)

	_, err = bindAgent(context.Background(), fakeBindings{}, identityLookupOf(), adoptRow(fcPolicyID), "0oa-agent", nil, federatedGrantIDJAG, step)
	require.Error(t, err)
	assert.Equal(t, "invalid_grant", oauthCode(err))
	assert.Contains(t, err.Error(), "no enabled binding", "the plain refusal, as with first contact off")
}

// Row writes: the policy must exist in the row's account and
// first_contact_project_id and be assignable there, checked when the write
// names it or moves the row to another project.
func TestCheckFirstContactPolicy(t *testing.T) {
	ctx := context.Background()
	past := time.Now().Add(-time.Minute)
	svc := func(store *fakePolicies) *ExternalIssuerService {
		return NewExternalIssuerService(nil, nil, nil, ExternalIssuerServiceConfig{Store: IssuerStoreDB, CredentialPolicies: store})
	}
	refusal := func(t *testing.T, err error) string {
		t.Helper()
		var apiErr *IssuerAPIError
		require.ErrorAs(t, err, &apiErr)
		assert.Equal(t, http.StatusBadRequest, apiErr.Status)
		assert.Equal(t, "first_contact_policy_invalid", apiErr.Code)
		return apiErr.Message
	}

	t.Run("no policy: nothing to check", func(t *testing.T) {
		store := policyStore(nil)
		require.NoError(t, svc(store).checkFirstContactPolicy(ctx, adoptRow(""), nil, true))
		assert.Empty(t, store.reads)
	})

	t.Run("a usable policy, unlocked before the transaction and share-locked in it", func(t *testing.T) {
		store := policyStore(nil)
		require.NoError(t, svc(store).checkFirstContactPolicy(ctx, adoptRow(fcPolicyID), nil, false))
		require.NoError(t, svc(store).checkFirstContactPolicy(ctx, adoptRow(fcPolicyID), nil, true))
		assert.Equal(t, []string{"get acct-a|proj-fc|" + fcPolicyID, "share acct-a|proj-fc|" + fcPolicyID}, store.reads)
	})

	for name, tc := range map[string]struct {
		store *fakePolicies
		id    string
		says  string
	}{
		"missing":            {policyStore(nil), fcOtherPolicy, "names no credential policy in first_contact_project_id"},
		"not a policy id":    {policyStore(nil), "policy-name", "names no credential policy"},
		"inactive":           {policyStore(func(p *domain.CredentialPolicy) { p.IsActive = false }), fcPolicyID, `"workloads", which is inactive`},
		"expired":            {policyStore(func(p *domain.CredentialPolicy) { p.ExpiresAt = &past }), fcPolicyID, "has expired"},
		"lists ciba:approve": {policyStore(func(p *domain.CredentialPolicy) { p.AllowedScopes = []string{domain.ScopeCIBAApprove} }), fcPolicyID, "approval channel"},
	} {
		t.Run("refused: "+name, func(t *testing.T) {
			msg := refusal(t, svc(tc.store).checkFirstContactPolicy(ctx, adoptRow(tc.id), nil, true))
			assert.Contains(t, msg, tc.says)
		})
	}

	t.Run("an update that keeps the policy and the project reads nothing", func(t *testing.T) {
		// Inactive since it was set: a rename or a disable must still go
		// through; adoption fails closed instead.
		store := policyStore(func(p *domain.CredentialPolicy) { p.IsActive = false })
		before := adoptRow(fcPolicyID)
		after := *before
		after.DisplayName, after.Enabled = "Renamed", false
		require.NoError(t, svc(store).checkFirstContactPolicy(ctx, &after, before, true))
		assert.Empty(t, store.reads)
	})

	t.Run("a project change re-checks the kept policy in the new project", func(t *testing.T) {
		store := policyStore(nil)
		before := adoptRow(fcPolicyID)
		after := *before
		after.FirstContactProjectID = "proj-2"
		msg := refusal(t, svc(store).checkFirstContactPolicy(ctx, &after, before, true))
		assert.Contains(t, msg, `first_contact_project_id "proj-2"`)
		assert.Equal(t, []string{"share acct-a|proj-2|" + fcPolicyID}, store.reads)
	})

	t.Run("a project change with a policy from the new project", func(t *testing.T) {
		store := policyStore(nil)
		store.policies[store.key(fcOtherPolicy, "acct-a", "proj-2")] = fcPolicy(fcOtherPolicy)
		before := adoptRow(fcPolicyID)
		after := *before
		after.FirstContactProjectID, after.FirstContactCredentialPolicyID = "proj-2", fcOtherPolicy
		require.NoError(t, svc(store).checkFirstContactPolicy(ctx, &after, before, true))
	})

	t.Run("a new policy on an existing row is checked", func(t *testing.T) {
		store := policyStore(func(p *domain.CredentialPolicy) { p.IsActive = false })
		before := adoptRow("")
		after := *before
		after.FirstContactCredentialPolicyID = fcPolicyID
		refusal(t, svc(store).checkFirstContactPolicy(ctx, &after, before, true))
	})

	t.Run("a failed read is passed on, not a refusal", func(t *testing.T) {
		store := policyStore(nil)
		store.err = errors.New("connection reset")
		err := svc(store).checkFirstContactPolicy(ctx, adoptRow(fcPolicyID), nil, true)
		require.Error(t, err)
		var apiErr *IssuerAPIError
		assert.False(t, errors.As(err, &apiErr))
	})

	t.Run("no policy store refuses a write that names a policy", func(t *testing.T) {
		err := NewExternalIssuerService(nil, nil, nil, ExternalIssuerServiceConfig{Store: IssuerStoreDB}).
			checkFirstContactPolicy(ctx, adoptRow(fcPolicyID), nil, true)
		require.Error(t, err)
	})
}

// A create that names a policy on a row that does not adopt is refused by
// validation, before anything is read or fetched: the service has no
// repository and no policy store, so a later refusal would panic or differ.
func TestExternalIssuerCreate_PolicyOnlyWithAdopt(t *testing.T) {
	svc := NewExternalIssuerService(nil, nil, nil, ExternalIssuerServiceConfig{Store: IssuerStoreDB})
	for _, mode := range []domain.FirstContactMode{"", domain.FirstContactOff, domain.FirstContactDiscover} {
		t.Run("first_contact "+string(mode), func(t *testing.T) {
			_, _, err := svc.Create(context.Background(), "acct", "u", IssuerInput{
				Kind: domain.IssuerKindWorkload, Issuer: "https://cluster.example", Audiences: []string{"https://zeroid.example"},
				FirstContact: mode, FirstContactProjectID: "proj-fc", FirstContactCredentialPolicyID: fcPolicyID,
			})
			var apiErr *IssuerAPIError
			require.ErrorAs(t, err, &apiErr)
			assert.Equal(t, http.StatusBadRequest, apiErr.Status)
			assert.Equal(t, "first_contact_policy_invalid", apiErr.Code)
		})
	}
}

// PATCH semantics: setting first_contact to off or discover clears the
// policy; naming one sets it; leaving both alone keeps it.
func TestApplyIssuerPatch_FirstContactPolicy(t *testing.T) {
	mode := func(m domain.FirstContactMode) *domain.FirstContactMode { return &m }
	for name, tc := range map[string]struct {
		patch     IssuerPatch
		want      string
		wantValid bool
	}{
		"off clears it":                {IssuerPatch{FirstContact: mode(domain.FirstContactOff)}, "", true},
		"discover clears it":           {IssuerPatch{FirstContact: mode(domain.FirstContactDiscover)}, "", true},
		"adopt, as it was, keeps it":   {IssuerPatch{FirstContact: mode(domain.FirstContactAdopt)}, fcPolicyID, true},
		"a rename keeps it":            {IssuerPatch{DisplayName: ptr("Renamed")}, fcPolicyID, true},
		"an owner change keeps it":     {IssuerPatch{FirstContactOwnerUserID: ptr("owner-2")}, fcPolicyID, true},
		"naming another sets it":       {IssuerPatch{FirstContactCredentialPolicyID: ptr(fcOtherPolicy)}, fcOtherPolicy, true},
		"an empty string clears it":    {IssuerPatch{FirstContactCredentialPolicyID: ptr("")}, "", true},
		"off naming one is refused":    {IssuerPatch{FirstContact: mode(domain.FirstContactOff), FirstContactCredentialPolicyID: ptr(fcOtherPolicy)}, fcOtherPolicy, false},
		"discover naming one, refused": {IssuerPatch{FirstContact: mode(domain.FirstContactDiscover), FirstContactCredentialPolicyID: ptr(fcPolicyID)}, fcPolicyID, false},
	} {
		t.Run(name, func(t *testing.T) {
			r := adoptRow(fcPolicyID)
			applyIssuerPatch(r, tc.patch)
			r.Normalize()
			assert.Equal(t, tc.want, r.FirstContactCredentialPolicyID)
			err := r.ValidateFirstContact()
			if tc.wantValid {
				require.NoError(t, err)
				return
			}
			var ve *domain.IssuerValidationError
			require.ErrorAs(t, err, &ve)
			assert.Equal(t, "first_contact_policy_invalid", ve.Code)
		})
	}

	t.Run("switching adopt off and on again does not bring the policy back", func(t *testing.T) {
		r := adoptRow(fcPolicyID)
		applyIssuerPatch(r, IssuerPatch{FirstContact: mode(domain.FirstContactDiscover)})
		applyIssuerPatch(r, IssuerPatch{FirstContact: mode(domain.FirstContactAdopt)})
		assert.Empty(t, r.FirstContactCredentialPolicyID)
	})
}

// The delete guard's service mapping: a first-contact reference is "in use",
// and says so, so the handler can name it.
func TestPolicyDeleteError(t *testing.T) {
	fcRef := fmt.Errorf("%w: %w: named by the first-contact mapping of 1 issuer row(s)",
		postgres.ErrCredentialPolicyInUse, postgres.ErrCredentialPolicyFirstContactReference)
	got := policyDeleteError(fcRef)
	assert.ErrorIs(t, got, ErrPolicyInUse)
	assert.ErrorIs(t, got, ErrPolicyInUseByFirstContact)

	keys := policyDeleteError(fmt.Errorf("%w: referenced by 2 service key(s)", postgres.ErrCredentialPolicyInUse))
	assert.ErrorIs(t, keys, ErrPolicyInUse)
	assert.NotErrorIs(t, keys, ErrPolicyInUseByFirstContact)

	assert.ErrorIs(t, policyDeleteError(postgres.ErrCredentialPolicyNotFound), ErrPolicyNotFound)
	assert.NoError(t, policyDeleteError(nil))
	other := errors.New("boom")
	assert.Equal(t, other, policyDeleteError(other))
}
