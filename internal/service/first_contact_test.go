package service

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

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

	register := func(b fakeBindings, key string, binding *domain.IssuerBinding, calls *int) firstContactFunc {
		return func(context.Context) (bool, error) {
			*calls++
			if binding == nil {
				return false, nil
			}
			b["row-1|"+key] = binding
			return true, nil
		}
	}

	t.Run("discover: the registered agent is refused, naming its state", func(t *testing.T) {
		b, calls := fakeRegistering{fakeBindings{}}, 0
		_, err := bindAgent(ctx, b, lookup, row, "sa", nil, federatedGrantClientCredentials,
			register(b.fakeBindings, "sa", &domain.IssuerBinding{IdentityID: "fc-1"}, &calls))
		require.Error(t, err)
		assert.Equal(t, "invalid_grant", oauthCode(err))
		assert.Contains(t, err.Error(), "discovered")
		assert.Equal(t, 1, calls)
	})

	t.Run("adopt: the registered agent is served", func(t *testing.T) {
		b, calls := fakeRegistering{fakeBindings{}}, 0
		got, err := bindAgent(ctx, b, lookup, row, "sa", nil, federatedGrantClientCredentials,
			register(b.fakeBindings, "sa", &domain.IssuerBinding{IdentityID: "fc-2", Enabled: true}, &calls))
		require.NoError(t, err)
		assert.Equal(t, "fc-2", got.ID)
	})

	t.Run("declined or past a bound: the plain no-binding refusal", func(t *testing.T) {
		b, calls := fakeRegistering{fakeBindings{}}, 0
		_, err := bindAgent(ctx, b, lookup, row, "sa", nil, federatedGrantClientCredentials,
			register(b.fakeBindings, "sa", nil, &calls))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no enabled binding")
		assert.Equal(t, 1, calls)
	})

	t.Run("a disabled binding never reaches first contact", func(t *testing.T) {
		b, calls := fakeRegistering{fakeBindings{"row-1|sa": {IdentityID: "agent-1", Enabled: false}}}, 0
		_, err := bindAgent(ctx, b, lookup, row, "sa", nil, federatedGrantClientCredentials,
			register(b.fakeBindings, "sa", &domain.IssuerBinding{IdentityID: "fc-2", Enabled: true}, &calls))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no enabled binding")
		assert.Zero(t, calls)
	})

	t.Run("an enabled binding never reaches first contact", func(t *testing.T) {
		b, calls := fakeRegistering{fakeBindings{"row-1|sa": {IdentityID: "agent-1", Enabled: true}}}, 0
		got, err := bindAgent(ctx, b, lookup, row, "sa", nil, federatedGrantClientCredentials,
			register(b.fakeBindings, "sa", nil, &calls))
		require.NoError(t, err)
		assert.Equal(t, "agent-1", got.ID)
		assert.Zero(t, calls)
	})
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
