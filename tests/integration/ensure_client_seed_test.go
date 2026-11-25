// Operator seeding of service identities and their OAuth clients: idempotent
// on the seed's own rows, and refusing rows it cannot show it owns.
package integration_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/google/uuid"

	zeroid "github.com/highflame-ai/zeroid"
	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// ── EnsureClient and EnsureServiceIdentity ───────────────────────────────────

func clientRowByClientID(t *testing.T, clientID string) *domain.OAuthClient {
	t.Helper()
	row := new(domain.OAuthClient)
	require.NoError(t, testDB.NewSelect().Model(row).Where("client_id = ?", clientID).Scan(context.Background()))
	return row
}

func seedServiceIdentity(t *testing.T, accountID, projectID string) *domain.Identity {
	t.Helper()
	id, err := testZeroIDServer.EnsureServiceIdentity(context.Background(), zeroid.ServiceIdentityConfig{
		AccountID: accountID, ProjectID: projectID, ExternalID: uid("svc"), OwnerUserID: "operator",
	})
	require.NoError(t, err)
	return id
}

func TestEnsureServiceIdentity(t *testing.T) {
	ctx := context.Background()
	acct, proj := uid("svc-acct"), uid("svc-proj")
	cfg := zeroid.ServiceIdentityConfig{AccountID: acct, ProjectID: proj, ExternalID: uid("gateway"), OwnerUserID: "operator"}

	first, err := testZeroIDServer.EnsureServiceIdentity(ctx, cfg)
	require.NoError(t, err)
	assert.Equal(t, domain.IdentityTypeService, first.IdentityType)
	assert.Equal(t, domain.TrustLevelFirstParty, first.TrustLevel, "a platform service is first party by default")
	assert.Equal(t, cfg.ExternalID, first.Name, "the name defaults to the external id")

	again, err := testZeroIDServer.EnsureServiceIdentity(ctx, cfg)
	require.NoError(t, err)
	assert.Equal(t, first.ID, again.ID, "idempotent: the same row, not a second one")

	t.Run("concurrent seeding converges on one identity", func(t *testing.T) {
		cfg := cfg
		cfg.ExternalID = uid("gateway-race")
		var wg sync.WaitGroup
		ids := make([]string, 8)
		errs := make([]error, 8)
		for i := range ids {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				id, err := testZeroIDServer.EnsureServiceIdentity(ctx, cfg)
				errs[i] = err
				if id != nil {
					ids[i] = id.ID
				}
			}(i)
		}
		wg.Wait()
		for i := range ids {
			require.NoError(t, errs[i])
			assert.Equal(t, ids[0], ids[i])
		}
	})

	t.Run("an identity of another type is not adopted", func(t *testing.T) {
		headers := tenantHeaders(acct, proj)
		agent := registerIdentityIn(t, headers, uid("not-a-service"), nil)
		_, err := testZeroIDServer.EnsureServiceIdentity(ctx, zeroid.ServiceIdentityConfig{
			AccountID: acct, ProjectID: proj, ExternalID: agent.ExternalID, OwnerUserID: "operator",
		})
		assert.True(t, errors.Is(err, zeroid.ErrServiceIdentityConflict), "got %v", err)
	})

	t.Run("required fields", func(t *testing.T) {
		_, err := testZeroIDServer.EnsureServiceIdentity(ctx, zeroid.ServiceIdentityConfig{AccountID: acct, ProjectID: proj})
		assert.Error(t, err)
	})
}

// A linked seed is the shape a platform service's client takes: created
// linked, adopted again on every start, and nothing else under its name.
func TestEnsureClient_LinkedSeed(t *testing.T) {
	ctx := context.Background()
	acct, proj := uid("seed-acct"), uid("seed-proj")
	svc := seedServiceIdentity(t, acct, proj)
	key := generateKey(t)
	seed := func(clientID, name string) zeroid.OAuthClientConfig {
		jwks, err := json.Marshal(clientJWKS(t, key))
		require.NoError(t, err)
		return zeroid.OAuthClientConfig{
			ClientID: clientID, Name: name, IdentityID: svc.ID,
			TokenEndpointAuthMethod: "private_key_jwt", JWKS: jwks,
			GrantTypes: []string{"client_credentials"}, Scopes: []string{"svc:ping"},
		}
	}

	t.Run("creates, then reconciles its own row", func(t *testing.T) {
		clientID := uid("svc-client")
		require.NoError(t, testZeroIDServer.EnsureClient(ctx, seed(clientID, "first")))
		row := clientRowByClientID(t, clientID)
		require.NotNil(t, row.IdentityID)
		assert.Equal(t, svc.ID, *row.IdentityID)
		assert.Equal(t, domain.RegistrationSourceSeed, row.RegistrationSource)

		require.NoError(t, testZeroIDServer.EnsureClient(ctx, seed(clientID, "renamed")))
		assert.Equal(t, "renamed", clientRowByClientID(t, clientID).Name)

		// The seeded client authenticates with its key and mints in the
		// identity's tenant, carrying its client_id.
		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type":            "client_credentials",
			"client_id":             clientID,
			"client_assertion":      clientAssertionFor(t, key, clientID),
			"client_assertion_type": clientAssertionType,
			"scope":                 "svc:ping",
		}, nil)
		body := decode(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode, "%v", body)
		claims := decodeJWTPayload(t, body["access_token"].(string))
		assert.Equal(t, clientID, claims["client_id"])
		assert.Equal(t, acct, claims["account_id"])
		assert.Equal(t, svc.WIMSEURI, claims["sub"])
	})

	t.Run("refuses a row linked to another identity", func(t *testing.T) {
		clientID := uid("svc-squat")
		squatTenant := tenantHeaders(uid("squat-acct"), "p")
		other := registerIdentityIn(t, squatTenant, uid("squatter"), nil)
		linkedClient(t, clientID, other.ID, squatTenant)
		before := clientRowByClientID(t, clientID)

		err := testZeroIDServer.EnsureClient(ctx, seed(clientID, "platform"))
		require.True(t, errors.Is(err, zeroid.ErrClientNotOwned), "got %v", err)
		after := clientRowByClientID(t, clientID)
		assert.Equal(t, before.Name, after.Name, "the row is left as its owner registered it")
		assert.Equal(t, other.ID, *after.IdentityID)
		assert.Equal(t, before.TokenEndpointAuthMethod, after.TokenEndpointAuthMethod)
	})

	t.Run("refuses a row linked to the same identity but not seeded", func(t *testing.T) {
		// Anyone who can register a client in the service identity's tenant
		// could link one to it before the first seed, and would hold its
		// secret. The link alone does not make the row the seed's.
		clientID := uid("svc-prelinked")
		linkedClient(t, clientID, svc.ID, tenantHeaders(acct, proj))
		err := testZeroIDServer.EnsureClient(ctx, seed(clientID, "platform"))
		require.True(t, errors.Is(err, zeroid.ErrClientNotOwned), "got %v", err)
		assert.Equal(t, "client_secret_basic", clientRowByClientID(t, clientID).TokenEndpointAuthMethod,
			"the row is left as registered")
	})

	t.Run("refuses an unlinked row", func(t *testing.T) {
		clientID := uid("svc-unlinked")
		registerOAuthClient(t, clientID, nil)
		err := testZeroIDServer.EnsureClient(ctx, seed(clientID, "platform"))
		require.True(t, errors.Is(err, zeroid.ErrClientNotOwned), "got %v", err)
		assert.Nil(t, clientRowByClientID(t, clientID).IdentityID, "the row is not linked by adoption")
	})

	t.Run("concurrent seeding converges on one row", func(t *testing.T) {
		clientID := uid("svc-race")
		var wg sync.WaitGroup
		errs := make([]error, 8)
		for i := range errs {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				errs[i] = testZeroIDServer.EnsureClient(ctx, seed(clientID, "race"))
			}(i)
		}
		wg.Wait()
		for _, err := range errs {
			require.NoError(t, err)
		}
		assert.Equal(t, svc.ID, *clientRowByClientID(t, clientID).IdentityID)
	})
}

// An unlinked seed (a first-party public client, say) keeps working on its own
// row and refuses rows it cannot be the owner of.
func TestEnsureClient_UnlinkedSeed(t *testing.T) {
	ctx := context.Background()
	publicSeed := func(clientID string) zeroid.OAuthClientConfig {
		return zeroid.OAuthClientConfig{
			ClientID: clientID, Name: "cli", GrantTypes: []string{"authorization_code"},
			RedirectURIs: []string{testRedirectURI},
		}
	}

	t.Run("refuses a row linked to an identity", func(t *testing.T) {
		clientID := uid("cli-linked")
		owner := registerIdentityIn(t, adminHeaders(), uid("cli-owner"), nil)
		linkedClient(t, clientID, owner.ID, adminHeaders())
		before := clientRowByClientID(t, clientID)

		err := testZeroIDServer.EnsureClient(ctx, publicSeed(clientID))
		require.True(t, errors.Is(err, zeroid.ErrClientNotOwned), "got %v", err)
		after := clientRowByClientID(t, clientID)
		assert.Equal(t, before.RedirectURIs, after.RedirectURIs, "the seed's redirect URIs are not written onto the row")
		assert.Equal(t, before.Name, after.Name)
	})

	t.Run("a public seed refuses a confidential row", func(t *testing.T) {
		clientID := uid("cli-conf")
		registerOAuthClient(t, clientID, nil) // confidential: someone holds its secret
		err := testZeroIDServer.EnsureClient(ctx, publicSeed(clientID))
		require.True(t, errors.Is(err, zeroid.ErrClientNotOwned), "got %v", err)
		assert.Empty(t, clientRowByClientID(t, clientID).RedirectURIs)
	})

	t.Run("a confidential seed refuses a public row", func(t *testing.T) {
		clientID := uid("cli-public")
		require.NoError(t, testZeroIDServer.EnsureClient(ctx, publicSeed(clientID)))
		err := testZeroIDServer.EnsureClient(ctx, zeroid.OAuthClientConfig{
			ClientID: clientID, Name: "svc", Confidential: true, GrantTypes: []string{"client_credentials"},
		})
		require.True(t, errors.Is(err, zeroid.ErrClientNotOwned), "got %v", err)
		assert.Equal(t, "none", clientRowByClientID(t, clientID).TokenEndpointAuthMethod)
	})

	t.Run("adopts a public row registered elsewhere, and records it as seeded", func(t *testing.T) {
		// A row registered before seeding recorded itself reads "internal",
		// like one from the admin route. It is adopted (and logged), as before.
		clientID := uid("cli-legacy")
		resp := post(t, adminPath("/oauth/clients"), map[string]any{
			"client_id": clientID, "name": "legacy", "grant_types": []string{"authorization_code"},
			"redirect_uris": []string{testRedirectURI},
		}, nil)
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		_ = resp.Body.Close()
		require.Equal(t, "internal", clientRowByClientID(t, clientID).RegistrationSource)

		require.NoError(t, testZeroIDServer.EnsureClient(ctx, publicSeed(clientID)))
		assert.Equal(t, domain.RegistrationSourceSeed, clientRowByClientID(t, clientID).RegistrationSource)
	})

	t.Run("refuses a dynamically registered row", func(t *testing.T) {
		// Its registrant holds a registration access token and could rewrite
		// the seed's configuration through RFC 7592.
		clientID := uid("cli-dynamic")
		require.NoError(t, testZeroIDServer.EnsureClient(ctx, publicSeed(clientID)))
		_, err := testDB.ExecContext(ctx, "UPDATE oauth_clients SET registration_source = 'dynamic' WHERE client_id = ?", clientID)
		require.NoError(t, err)
		err = testZeroIDServer.EnsureClient(ctx, publicSeed(clientID))
		require.True(t, errors.Is(err, zeroid.ErrClientNotOwned), "got %v", err)
	})

	t.Run("a public seed still adopts its own public row", func(t *testing.T) {
		clientID := uid("cli-own")
		require.NoError(t, testZeroIDServer.EnsureClient(ctx, publicSeed(clientID)))
		cfg := publicSeed(clientID)
		cfg.Name = "cli renamed"
		require.NoError(t, testZeroIDServer.EnsureClient(ctx, cfg))
		assert.Equal(t, "cli renamed", clientRowByClientID(t, clientID).Name)
	})
}

// An update of a row that no longer exists is an error, not a silent success:
// EnsureClient read the row, and it was deleted (and its client_id perhaps
// re-registered by someone else) before the write.
func TestOAuthClientRepository_UpdateOfMissingRowFails(t *testing.T) {
	repo := postgres.NewOAuthClientRepository(testDB)
	err := repo.Update(context.Background(), &domain.OAuthClient{ID: uuid.NewString(), ClientID: uid("gone"), Name: "gone"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, sql.ErrNoRows), "got %v", err)
}
