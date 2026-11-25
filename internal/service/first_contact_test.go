package service

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
)

func TestFirstContactExternalID(t *testing.T) {
	const row = "6f1c2b9e-0000-4000-8000-000000000001"

	t.Run("an opaque client id keeps its form, in the reserved namespace", func(t *testing.T) {
		id := firstContactExternalID(row, "0oa8f5j3ecb5w3dF35d7")
		assert.Equal(t, "first_contact.0oa8f5j3ecb5w3dF35d7", id)
		assert.NotEqual(t, "0oa8f5j3ecb5w3dF35d7", id, "never the id another record has under the same key")
		assert.True(t, reservedFirstContactExternalID(id))
		require.NoError(t, domain.ValidateSPIFFEPathSegment("external_id", id))
	})

	for _, key := range []string{
		"arn:aws:iam::123456789012:role/service-role/AgentRuntime",
		"system:serviceaccount:agents:planner",
		"spiffe://example.org/ns/agents/sa/planner",
		"https://agent.example/cimd.json",
		strings.Repeat("x", 129),
		strings.Repeat("arn:aws:iam::123456789012:role/", 20),
	} {
		t.Run("a subject that is not a path segment: "+key[:min(len(key), 40)], func(t *testing.T) {
			id := firstContactExternalID(row, key)
			require.NoError(t, domain.ValidateSPIFFEPathSegment("external_id", id), id)
			assert.True(t, reservedFirstContactExternalID(id), id)
			assert.LessOrEqual(t, len(id), 255)
			assert.Equal(t, id, firstContactExternalID(row, key), "deterministic")
			assert.NotEqual(t, id, firstContactExternalID("6f1c2b9e-0000-4000-8000-000000000002", key),
				"another issuer row's subject is another agent")
		})
	}

	t.Run("two keys with the same readable part stay apart", func(t *testing.T) {
		a := firstContactExternalID(row, "system:serviceaccount:a:b")
		b := firstContactExternalID(row, "system:serviceaccount:a/b")
		assert.NotEqual(t, a, b)
		assert.True(t, strings.HasPrefix(a, "first_contact.system_serviceaccount_a_b-"), a)
	})
}

// No caller but first contact can take an external_id in its namespace: not
// an admin registration, and not a discovered ingest, which is refused before
// it looks up the external_id, so an inventory record never reconciles into a
// first-contact identity by external_id.
func TestFirstContactExternalIDReserved(t *testing.T) {
	s := &IdentityService{}
	ctx := context.Background()
	_, err := s.RegisterIdentity(ctx, RegisterIdentityRequest{
		AccountID: "a", ProjectID: "p", ExternalID: "first_contact.0oa1", OwnerUserID: "o",
	})
	require.ErrorIs(t, err, ErrInvalidIdentityField)
	assert.ErrorIs(t, err, errFirstContactExternalIDReserved)

	_, _, err = s.UpsertDiscoveredIdentity(ctx, DiscoveredIdentityRequest{
		AccountID: "a", ProjectID: "p", ExternalID: "first_contact.0oa1", Origin: "inventory",
	})
	require.ErrorIs(t, err, ErrInvalidIdentityField)
	assert.ErrorIs(t, err, errFirstContactExternalIDReserved)

	assert.False(t, reservedFirstContactExternalID("0oa1"))
	assert.False(t, reservedFirstContactExternalID("first_contact"), "the origin name alone is no external_id in the namespace")
	assert.False(t, reservedFirstContactExternalID("First_Contact.0oa1"), "external ids are case-sensitive")
}

func TestFirstContactName(t *testing.T) {
	assert.Equal(t, "arn:aws:iam::1:role/x", firstContactName("arn:aws:iam::1:role/x"))
	long := strings.Repeat("é", 200) // 400 bytes
	got := firstContactName(long)
	assert.LessOrEqual(t, len(got), 255)
	assert.True(t, strings.HasPrefix(long, got))
	assert.True(t, json.Valid([]byte(`"`+got+`"`)), "cut on a character boundary")
}

func TestAWSSTSClaims(t *testing.T) {
	t.Run("keeps the account, organization, paths and principal tags, never request tags", func(t *testing.T) {
		got := awsSTSClaims(map[string]any{
			"sub": "arn:aws:iam::123456789012:role/AgentRuntime",
			awsSTSClaimNamespace: map[string]any{
				"aws_account":    "123456789012",
				"source_region":  "us-east-1",
				"org_id":         "o-abc1234567",
				"ou_path":        []any{"o-a1b2c3d4e5/r-ab12/ou-ab12-11111111/", 7, ""},
				"principal_tags": map[string]any{"team": "payments", "count": 3},
				"request_tags":   map[string]any{"chosen": "by the caller"},
			},
		})
		assert.Equal(t, map[string]any{
			"account":        "123456789012",
			"org_id":         "o-abc1234567",
			"ou_path":        []string{"o-a1b2c3d4e5/r-ab12/ou-ab12-11111111/"},
			"principal_tags": map[string]string{"team": "payments"},
		}, got)
	})

	t.Run("nothing for a token without the namespace, or with the wrong shape", func(t *testing.T) {
		assert.Nil(t, awsSTSClaims(map[string]any{"sub": "system:serviceaccount:a:b"}))
		assert.Nil(t, awsSTSClaims(map[string]any{awsSTSClaimNamespace: "not an object"}))
		assert.Nil(t, awsSTSClaims(map[string]any{awsSTSClaimNamespace: map[string]any{"aws_account": 12}}))
		assert.Nil(t, awsSTSClaims(nil))
	})

	t.Run("oversized values are dropped", func(t *testing.T) {
		tags := map[string]any{}
		for i := range maxAWSTags + 1 {
			tags[strings.Repeat("k", i+1)] = "v"
		}
		got := awsSTSClaims(map[string]any{awsSTSClaimNamespace: map[string]any{
			"aws_account":    strings.Repeat("1", maxAWSIDBytes+1),
			"principal_tags": tags,
		}})
		assert.Nil(t, got)
	})
}

func TestKeepFirstContactProvenance(t *testing.T) {
	prevLabels := json.RawMessage(`{"discovered_via":"first_contact"}`)
	prevMetadata := json.RawMessage(`{"first_contact":{"subject_key":"arn:aws:iam::1:role/x"},"note":"old"}`)

	t.Run("an inventory update keeps the marker and the arrival record", func(t *testing.T) {
		id := &domain.Identity{Origin: domain.OriginFirstContact,
			Labels:   json.RawMessage(`{"team":"a","discovered_via":"inventory"}`),
			Metadata: json.RawMessage(`{"runtime":"r1","first_contact":{"subject_key":"forged"}}`)}
		keepFirstContactProvenance(id, prevLabels, prevMetadata)
		assert.JSONEq(t, `{"team":"a","discovered_via":"first_contact"}`, string(id.Labels))
		assert.JSONEq(t, `{"runtime":"r1","first_contact":{"subject_key":"arn:aws:iam::1:role/x"}}`, string(id.Metadata))
	})

	t.Run("values that are not objects are put back", func(t *testing.T) {
		id := &domain.Identity{Origin: domain.OriginFirstContact, Labels: json.RawMessage(`[1]`), Metadata: json.RawMessage(`"x"`)}
		keepFirstContactProvenance(id, prevLabels, prevMetadata)
		assert.JSONEq(t, string(prevLabels), string(id.Labels))
		assert.JSONEq(t, string(prevMetadata), string(id.Metadata))
	})

	t.Run("any other identity is left alone", func(t *testing.T) {
		id := &domain.Identity{Origin: domain.OriginOkta, Labels: json.RawMessage(`{"a":"b"}`), Metadata: json.RawMessage(`{}`)}
		keepFirstContactProvenance(id, prevLabels, prevMetadata)
		assert.JSONEq(t, `{"a":"b"}`, string(id.Labels))
		assert.JSONEq(t, `{}`, string(id.Metadata))
	})
}

// fakeRegistering is a binding source whose first-contact step adds a
// binding, the way a registration commits one before bindAgent reads again.
type fakeRegistering struct {
	fakeBindings
}

func TestBindAgent_FirstContact(t *testing.T) {
	row := &domain.ExternalIssuer{ID: "row-1", AccountID: "acct-a", Issuer: "https://idp"}
	discovered := &domain.Identity{ID: "fc-1", AccountID: "acct-a", ProjectID: "proj-fc", Status: domain.IdentityStatusDiscovered}
	adopted := &domain.Identity{ID: "fc-2", AccountID: "acct-a", ProjectID: "proj-fc", Status: domain.IdentityStatusActive}
	active := &domain.Identity{ID: "agent-1", AccountID: "acct-a", ProjectID: "proj-1", Status: domain.IdentityStatusActive}
	lookup := identityLookupOf(discovered, adopted, active)
	ctx := context.Background()

	// register binds key the way a registration or a standing adoption
	// commits before bindAgent reads again, and records what bindAgent passed.
	register := func(b fakeBindings, key string, binding *domain.IssuerBinding, calls *int, seen *[]*domain.IssuerBinding) firstContactFunc {
		return func(_ context.Context, existing []*domain.IssuerBinding) (bool, error) {
			*calls++
			*seen = existing
			if binding == nil {
				return false, nil
			}
			b["row-1|"+key] = binding
			return true, nil
		}
	}

	t.Run("discover: the registered agent is refused, naming its state", func(t *testing.T) {
		b, calls, seen := fakeRegistering{fakeBindings{}}, 0, []*domain.IssuerBinding(nil)
		_, err := bindAgent(ctx, b, lookup, row, "sa", nil, federatedGrantClientCredentials,
			register(b.fakeBindings, "sa", &domain.IssuerBinding{IdentityID: "fc-1"}, &calls, &seen))
		require.Error(t, err)
		assert.Equal(t, "invalid_grant", oauthCode(err))
		assert.Contains(t, err.Error(), "discovered")
		assert.Equal(t, 1, calls)
		assert.Empty(t, seen, "no binding before the registration")
	})

	t.Run("adopt: the registered agent is served", func(t *testing.T) {
		b, calls, seen := fakeRegistering{fakeBindings{}}, 0, []*domain.IssuerBinding(nil)
		got, err := bindAgent(ctx, b, lookup, row, "sa", nil, federatedGrantClientCredentials,
			register(b.fakeBindings, "sa", &domain.IssuerBinding{IdentityID: "fc-2", Enabled: true}, &calls, &seen))
		require.NoError(t, err)
		assert.Equal(t, "fc-2", got.ID)
	})

	t.Run("declined or past a bound: the plain no-binding refusal", func(t *testing.T) {
		b, calls, seen := fakeRegistering{fakeBindings{}}, 0, []*domain.IssuerBinding(nil)
		_, err := bindAgent(ctx, b, lookup, row, "sa", nil, federatedGrantClientCredentials,
			register(b.fakeBindings, "sa", nil, &calls, &seen))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no enabled binding")
		assert.Equal(t, 1, calls)
	})

	t.Run("a disabled binding reaches first contact, which is passed the binding", func(t *testing.T) {
		disabled := &domain.IssuerBinding{IdentityID: "fc-1", Enabled: false}
		b, calls, seen := fakeRegistering{fakeBindings{"row-1|sa": disabled}}, 0, []*domain.IssuerBinding(nil)
		_, err := bindAgent(ctx, b, lookup, row, "sa", nil, federatedGrantClientCredentials,
			register(b.fakeBindings, "sa", nil, &calls, &seen))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "agent identity is discovered", "declined: refused as today")
		assert.Equal(t, 1, calls)
		assert.Equal(t, []*domain.IssuerBinding{disabled}, seen)
	})

	t.Run("standing adoption: the agent it adopted is served", func(t *testing.T) {
		b, calls, seen := fakeRegistering{fakeBindings{"row-1|sa": {IdentityID: "fc-1", Enabled: false}}}, 0, []*domain.IssuerBinding(nil)
		// The adoption activates the identity and enables its binding; here,
		// the binding moves to an active identity, which reads the same.
		got, err := bindAgent(ctx, b, lookup, row, "sa", nil, federatedGrantClientCredentials,
			register(b.fakeBindings, "sa", &domain.IssuerBinding{IdentityID: "fc-2", Enabled: true}, &calls, &seen))
		require.NoError(t, err)
		assert.Equal(t, "fc-2", got.ID)
		assert.Equal(t, 1, calls)
	})

	t.Run("an enabled binding never reaches first contact", func(t *testing.T) {
		b, calls, seen := fakeRegistering{fakeBindings{"row-1|sa": {IdentityID: "agent-1", Enabled: true}}}, 0, []*domain.IssuerBinding(nil)
		got, err := bindAgent(ctx, b, lookup, row, "sa", nil, federatedGrantClientCredentials,
			register(b.fakeBindings, "sa", nil, &calls, &seen))
		require.NoError(t, err)
		assert.Equal(t, "agent-1", got.ID)
		assert.Zero(t, calls)
	})
}

// A discover row leaves an agent that is bound already, enabled or not, as it
// is: only an adopt row's step goes on to its prepare and the registrar.
func TestFirstContactFor_BoundAgent(t *testing.T) {
	s := &OAuthService{firstContact: &FirstContactRegistrar{}}
	disabled := []*domain.IssuerBinding{{IdentityID: "id-1"}}
	for _, mode := range []domain.FirstContactMode{domain.FirstContactDiscover, domain.FirstContactAdopt} {
		t.Run(string(mode), func(t *testing.T) {
			row := &domain.ExternalIssuer{ID: "r", AccountID: "a", Enabled: true, FirstContact: mode,
				FirstContactProjectID: "p", FirstContactOwnerUserID: "o"}
			prepared := false
			step := s.firstContactFor(row, "sa", federatedGrantClientCredentials, nil, func(context.Context) (firstContactOutcome, error) {
				prepared = true
				return firstContactRegisteredClient, nil
			})
			require.NotNil(t, step)
			reread, err := step(context.Background(), disabled)
			require.NoError(t, err)
			assert.False(t, reread)
			assert.Equal(t, mode == domain.FirstContactAdopt, prepared)
		})
	}
}

func TestStandingAdoptionBinding(t *testing.T) {
	one := &domain.IssuerBinding{ID: "b1", IdentityID: "id-1"}
	got, outcome := standingAdoptionBinding([]*domain.IssuerBinding{one})
	assert.Equal(t, one, got)
	assert.Empty(t, outcome)

	explicit := &domain.IssuerBinding{ID: "b2", IdentityID: "id-2", ExplicitlyDisabled: true}
	for name, tc := range map[string]struct {
		bindings []*domain.IssuerBinding
		want     firstContactOutcome
	}{
		"an explicit disable wins":                    {[]*domain.IssuerBinding{explicit}, firstContactExplicitlyDisabled},
		"an explicit disable on any binding wins":     {[]*domain.IssuerBinding{one, explicit}, firstContactExplicitlyDisabled},
		"two bindings leave the choice to a person":   {[]*domain.IssuerBinding{one, {ID: "b3", IdentityID: "id-3"}}, firstContactAmbiguousBinding},
		"no binding is no candidate (a registration)": {nil, firstContactAmbiguousBinding},
	} {
		t.Run(name, func(t *testing.T) {
			got, outcome := standingAdoptionBinding(tc.bindings)
			assert.Nil(t, got)
			assert.Equal(t, tc.want, outcome)
		})
	}
}

func TestStandingAdoptionRefusal(t *testing.T) {
	row := &domain.ExternalIssuer{ID: "row-1", AccountID: "acct-a", FirstContact: domain.FirstContactAdopt,
		FirstContactProjectID: "proj-fc", FirstContactOwnerUserID: "owner"}
	discovered := func() *domain.Identity {
		return &domain.Identity{ID: "id-1", AccountID: "acct-a", ProjectID: "proj-fc", Status: domain.IdentityStatusDiscovered}
	}
	disabled := func() *domain.IssuerBinding { return &domain.IssuerBinding{ID: "b1", IdentityID: "id-1"} }

	assert.Empty(t, standingAdoptionRefusal(row, disabled(), discovered()), "a discovered agent in the mapped project is adopted")

	for name, tc := range map[string]struct {
		binding  func(*domain.IssuerBinding)
		identity func(*domain.Identity)
		want     firstContactOutcome
	}{
		"an enabled binding is bound already":       {binding: func(b *domain.IssuerBinding) { b.Enabled = true }, want: firstContactAlreadyBound},
		"an explicitly disabled binding":            {binding: func(b *domain.IssuerBinding) { b.ExplicitlyDisabled = true }, want: firstContactExplicitlyDisabled},
		"a person took the agent on (pending)":      {identity: func(i *domain.Identity) { i.Status = domain.IdentityStatusPending }, want: firstContactNotDiscovered},
		"an active agent whose binding is disabled": {identity: func(i *domain.Identity) { i.Status = domain.IdentityStatusActive }, want: firstContactNotDiscovered},
		"a suspended agent":                         {identity: func(i *domain.Identity) { i.Status = domain.IdentityStatusSuspended }, want: firstContactNotDiscovered},
		"a dismissed agent":                         {identity: func(i *domain.Identity) { i.Status = domain.IdentityStatusDeactivated }, want: firstContactNotDiscovered},
		"an agent in another project":               {identity: func(i *domain.Identity) { i.ProjectID = "proj-other" }, want: firstContactOtherProject},
		"an agent in another account":               {identity: func(i *domain.Identity) { i.AccountID = "acct-b" }, want: firstContactOtherProject},
		"the explicit disable is named before the state": {
			binding:  func(b *domain.IssuerBinding) { b.ExplicitlyDisabled = true },
			identity: func(i *domain.Identity) { i.Status = domain.IdentityStatusPending },
			want:     firstContactExplicitlyDisabled,
		},
	} {
		t.Run(name, func(t *testing.T) {
			b, i := disabled(), discovered()
			if tc.binding != nil {
				tc.binding(b)
			}
			if tc.identity != nil {
				tc.identity(i)
			}
			assert.Equal(t, tc.want, standingAdoptionRefusal(row, b, i))
		})
	}
}

func TestFirstContactOutcomeRereads(t *testing.T) {
	for _, o := range []firstContactOutcome{firstContactRegistered, firstContactAdopted, firstContactAlreadyBound} {
		assert.True(t, o.rereads(), o)
	}
	for _, o := range []firstContactOutcome{
		firstContactRowChanged, firstContactRateLimited, firstContactAccountCap, firstContactExternalIDTaken,
		firstContactSubjectTooLong, firstContactRegisteredClient, firstContactExplicitlyDisabled,
		firstContactAmbiguousBinding, firstContactNotDiscovered, firstContactOtherProject, firstContactApprovalChannel,
	} {
		assert.False(t, o.rereads(), o)
	}
}

func TestFirstContactMarkers(t *testing.T) {
	setAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	row := &domain.ExternalIssuer{ID: "row-1", Issuer: "https://idp.example", FirstContactProjectID: "proj-fc",
		FirstContactOwnerUserID: "owner", FirstContactUpdatedBy: "user-admin", FirstContactUpdatedAt: &setAt}
	a := firstContactArrival{row: row, subjectKey: "sa", grant: federatedGrantClientCredentials}

	t.Run("discover: the first-contact markers only", func(t *testing.T) {
		fresh := *row
		fresh.FirstContact = domain.FirstContactDiscover
		labels, metadata, err := firstContactMarkers(a, &fresh)
		require.NoError(t, err)
		assert.JSONEq(t, `{"discovered_via":"first_contact"}`, string(labels))
		var m map[string]map[string]any
		require.NoError(t, json.Unmarshal(metadata, &m))
		assert.Equal(t, "discover", m["first_contact"]["mode"])
		assert.NotContains(t, m, "first_contact_adoption")
	})

	t.Run("adopt: the standing-adoption markers too, naming who set the mapping", func(t *testing.T) {
		fresh := *row
		fresh.FirstContact = domain.FirstContactAdopt
		labels, metadata, err := firstContactMarkers(a, &fresh)
		require.NoError(t, err)
		assert.JSONEq(t, `{"discovered_via":"first_contact","adopted_via":"first_contact"}`, string(labels))
		var m map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(metadata, &m))
		assert.JSONEq(t, `{"issuer":"https://idp.example","issuer_id":"row-1","subject_key":"sa",
			"grant_type":"client_credentials","mapping_updated_by":"user-admin","mapping_updated_at":"2026-01-02T03:04:05Z"}`,
			string(m["first_contact_adoption"]))
	})
}

func TestStandingAdoptionMarkers(t *testing.T) {
	row := &domain.ExternalIssuer{ID: "row-1", Issuer: "https://idp.example", FirstContactUpdatedBy: "user-admin"}
	a := firstContactArrival{row: row, subjectKey: "0oa-agent", grant: federatedGrantIDJAG}

	t.Run("added beside what the inventory wrote", func(t *testing.T) {
		id := &domain.Identity{Labels: json.RawMessage(`{"team":"payments"}`), Metadata: json.RawMessage(`{"runtime":"r1"}`)}
		labels, metadata, err := standingAdoptionMarkers(id, a, row)
		require.NoError(t, err)
		assert.JSONEq(t, `{"team":"payments","adopted_via":"first_contact"}`, string(labels))
		assert.JSONEq(t, `{"runtime":"r1","first_contact_adoption":{"issuer":"https://idp.example","issuer_id":"row-1",
			"subject_key":"0oa-agent","grant_type":"id_jag","mapping_updated_by":"user-admin"}}`, string(metadata))
	})

	t.Run("values that are not objects are replaced", func(t *testing.T) {
		id := &domain.Identity{Labels: json.RawMessage(`[1]`), Metadata: nil}
		labels, metadata, err := standingAdoptionMarkers(id, a, row)
		require.NoError(t, err)
		assert.JSONEq(t, `{"adopted_via":"first_contact"}`, string(labels))
		assert.Contains(t, string(metadata), `"first_contact_adoption"`)
	})
}

func TestKeepStandingAdoptionMarkers(t *testing.T) {
	prevLabels := json.RawMessage(`{"adopted_via":"first_contact","team":"a"}`)
	prevMetadata := json.RawMessage(`{"first_contact_adoption":{"issuer_id":"row-1"},"note":"old"}`)

	t.Run("an inventory update keeps them", func(t *testing.T) {
		id := &domain.Identity{Origin: "inventory", Labels: json.RawMessage(`{"team":"b"}`),
			Metadata: json.RawMessage(`{"runtime":"r1","first_contact_adoption":{"issuer_id":"forged"}}`)}
		keepStandingAdoptionMarkers(id, prevLabels, prevMetadata)
		assert.JSONEq(t, `{"team":"b","adopted_via":"first_contact"}`, string(id.Labels))
		assert.JSONEq(t, `{"runtime":"r1","first_contact_adoption":{"issuer_id":"row-1"}}`, string(id.Metadata))
	})

	t.Run("an inventory update cannot add them", func(t *testing.T) {
		id := &domain.Identity{Origin: "inventory", Labels: json.RawMessage(`{"team":"b","adopted_via":"first_contact"}`),
			Metadata: json.RawMessage(`{"first_contact_adoption":{"issuer_id":"forged"}}`)}
		keepStandingAdoptionMarkers(id, json.RawMessage(`{"team":"a"}`), json.RawMessage(`{}`))
		assert.JSONEq(t, `{"team":"b"}`, string(id.Labels))
		assert.JSONEq(t, `{}`, string(id.Metadata))
	})

	t.Run("nor can a new identity", func(t *testing.T) {
		id := &domain.Identity{Labels: json.RawMessage(`{"adopted_via":"first_contact"}`),
			Metadata: json.RawMessage(`{"first_contact_adoption":{}}`)}
		keepStandingAdoptionMarkers(id, nil, nil)
		assert.JSONEq(t, `{}`, string(id.Labels))
		assert.JSONEq(t, `{}`, string(id.Metadata))
	})

	t.Run("another adopted_via value is not the marker", func(t *testing.T) {
		id := &domain.Identity{Labels: json.RawMessage(`{"adopted_via":"inventory_review"}`), Metadata: json.RawMessage(`{}`)}
		keepStandingAdoptionMarkers(id, nil, nil)
		assert.JSONEq(t, `{"adopted_via":"inventory_review"}`, string(id.Labels))
	})

	t.Run("values that are not objects are put back when they would drop a marker", func(t *testing.T) {
		id := &domain.Identity{Labels: json.RawMessage(`[1]`), Metadata: json.RawMessage(`"x"`)}
		keepStandingAdoptionMarkers(id, prevLabels, prevMetadata)
		assert.JSONEq(t, string(prevLabels), string(id.Labels))
		assert.JSONEq(t, string(prevMetadata), string(id.Metadata))

		other := &domain.Identity{Labels: json.RawMessage(`[1]`), Metadata: json.RawMessage(`"x"`)}
		keepStandingAdoptionMarkers(other, nil, nil)
		assert.Equal(t, `[1]`, string(other.Labels), "no marker to keep: left alone")
		assert.Equal(t, `"x"`, string(other.Metadata))
	})

	t.Run("an identity without them is left alone", func(t *testing.T) {
		id := &domain.Identity{Labels: json.RawMessage(`{"a":"b"}`), Metadata: json.RawMessage(`{"c":1}`)}
		keepStandingAdoptionMarkers(id, json.RawMessage(`{}`), json.RawMessage(`{}`))
		assert.Equal(t, `{"a":"b"}`, string(id.Labels))
		assert.Equal(t, `{"c":1}`, string(id.Metadata))
	})
}

func TestStampFirstContact(t *testing.T) {
	t.Run("a new row with first contact off and no mapping names no one", func(t *testing.T) {
		r := &domain.ExternalIssuer{FirstContact: domain.FirstContactOff}
		stampFirstContact(r, nil, "user-a")
		assert.Empty(t, r.FirstContactUpdatedBy)
		assert.Nil(t, r.FirstContactUpdatedAt)
	})

	t.Run("a new row that sets it names its creator", func(t *testing.T) {
		r := &domain.ExternalIssuer{FirstContact: domain.FirstContactDiscover, FirstContactProjectID: "p"}
		stampFirstContact(r, nil, "user-a")
		assert.Equal(t, "user-a", r.FirstContactUpdatedBy)
		require.NotNil(t, r.FirstContactUpdatedAt)
	})

	setAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	stored := domain.ExternalIssuer{FirstContact: domain.FirstContactAdopt, FirstContactProjectID: "p", FirstContactOwnerUserID: "o",
		FirstContactUpdatedBy: "user-a", FirstContactUpdatedAt: &setAt}

	t.Run("an update that leaves the settings alone keeps who set them", func(t *testing.T) {
		r := stored
		r.DisplayName = "renamed"
		stampFirstContact(&r, &stored, "user-b")
		assert.Equal(t, "user-a", r.FirstContactUpdatedBy)
		assert.Equal(t, &setAt, r.FirstContactUpdatedAt)
	})

	for name, change := range map[string]func(*domain.ExternalIssuer){
		"the mode":    func(r *domain.ExternalIssuer) { r.FirstContact = domain.FirstContactDiscover },
		"the project": func(r *domain.ExternalIssuer) { r.FirstContactProjectID = "q" },
		"the owner":   func(r *domain.ExternalIssuer) { r.FirstContactOwnerUserID = "o2" },
	} {
		t.Run("an update of "+name+" names its author", func(t *testing.T) {
			r := stored
			change(&r)
			stampFirstContact(&r, &stored, "user-b")
			assert.Equal(t, "user-b", r.FirstContactUpdatedBy)
			require.NotNil(t, r.FirstContactUpdatedAt)
			assert.True(t, r.FirstContactUpdatedAt.After(setAt))
		})
	}
}

func TestFirstContactFor_Off(t *testing.T) {
	s := &OAuthService{firstContact: &FirstContactRegistrar{}}
	on := &domain.ExternalIssuer{ID: "r", Enabled: true, FirstContact: domain.FirstContactDiscover, FirstContactProjectID: "p"}
	assert.NotNil(t, s.firstContactFor(on, "sa", federatedGrantClientCredentials, nil, nil))

	off := *on
	off.FirstContact = domain.FirstContactOff
	disabled := *on
	disabled.Enabled = false
	for name, row := range map[string]*domain.ExternalIssuer{"off": &off, "disabled row": &disabled, "static issuer": nil} {
		assert.Nil(t, s.firstContactFor(row, "sa", federatedGrantClientCredentials, nil, nil), name)
	}
	assert.Nil(t, (&OAuthService{}).firstContactFor(on, "sa", federatedGrantClientCredentials, nil, nil), "no registrar")
}
