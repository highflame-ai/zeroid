// A client deleted between the read and the write of an update answers as a
// missing client, not as a server error; a store failure is not read as a
// missing client.
package integration_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/internal/service"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// vanishNamePrefix marks the clients skipVanishingUpdates applies to.
const vanishNamePrefix = "zeroid-test-vanish"

// skipVanishingUpdates installs a trigger that silently skips any UPDATE of an
// oauth_clients row whose name starts with vanishNamePrefix. To the service
// that is indistinguishable from the row having been deleted after it was
// read: the UPDATE matches nothing.
func skipVanishingUpdates(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	_, err := testDB.ExecContext(ctx, `
		CREATE OR REPLACE FUNCTION zeroid_test_skip_named_update() RETURNS trigger AS $$
		BEGIN
			IF OLD.name LIKE 'zeroid-test-vanish%' THEN
				RETURN NULL;
			END IF;
			RETURN NEW;
		END $$ LANGUAGE plpgsql`)
	require.NoError(t, err)
	_, err = testDB.ExecContext(ctx, `
		DROP TRIGGER IF EXISTS zeroid_test_skip_named_update ON oauth_clients;
		CREATE TRIGGER zeroid_test_skip_named_update BEFORE UPDATE ON oauth_clients
			FOR EACH ROW EXECUTE FUNCTION zeroid_test_skip_named_update()`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = testDB.ExecContext(context.Background(), `DROP TRIGGER IF EXISTS zeroid_test_skip_named_update ON oauth_clients`)
		_, _ = testDB.ExecContext(context.Background(), `DROP FUNCTION IF EXISTS zeroid_test_skip_named_update()`)
	})
}

func TestOAuthClient_UpdateOfVanishedRowIsNotFound(t *testing.T) {
	ctx := context.Background()
	svc := service.NewOAuthClientService(postgres.NewOAuthClientRepository(testDB))
	name := uid(vanishNamePrefix)
	skipVanishingUpdates(t)

	t.Run("rotate secret", func(t *testing.T) {
		client, _, err := svc.RegisterClient(ctx, service.RegisterClientRequest{
			ClientID: uid("vanish-rotate"), Name: name, Confidential: true,
			GrantTypes: []string{"client_credentials"},
		})
		require.NoError(t, err)
		_, _, err = svc.RotateSecret(ctx, client.ID)
		assert.True(t, errors.Is(err, service.ErrOAuthClientNotFound), "got %v", err)
	})

	t.Run("RFC 7592 update", func(t *testing.T) {
		client, _, _, err := svc.DynamicRegisterClient(ctx, service.DynamicRegisterClientRequest{
			Name: name, GrantTypes: []string{"client_credentials"},
		})
		require.NoError(t, err)
		_, err = svc.UpdateDynamicClient(ctx, client.ClientID, service.DynamicRegisterClientRequest{
			Name: name, GrantTypes: []string{"client_credentials"},
		})
		assert.True(t, errors.Is(err, service.ErrOAuthClientNotFound),
			"the handler answers a vanished client as 401 client no longer exists, got %v", err)
	})
}

func TestOAuthClient_GetByIDMapsOnlyMissingRowsToNotFound(t *testing.T) {
	svc := service.NewOAuthClientService(postgres.NewOAuthClientRepository(testDB))
	ctx := context.Background()

	_, err := svc.GetClient(ctx, "not-a-uuid")
	assert.True(t, errors.Is(err, service.ErrOAuthClientNotFound), "an id that cannot name a client: %v", err)
	_, err = svc.GetClient(ctx, "00000000-0000-4000-8000-000000000000")
	assert.True(t, errors.Is(err, service.ErrOAuthClientNotFound), "no such row: %v", err)

	// A failed query (here, a cancelled context) is not "no such client".
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = svc.GetClient(cancelled, "00000000-0000-4000-8000-000000000000")
	require.Error(t, err)
	assert.False(t, errors.Is(err, service.ErrOAuthClientNotFound), "a store failure read as not found")
	_, _, err = svc.RotateSecret(cancelled, "00000000-0000-4000-8000-000000000000")
	require.Error(t, err)
	assert.False(t, errors.Is(err, service.ErrOAuthClientNotFound), "a store failure read as not found")
}
