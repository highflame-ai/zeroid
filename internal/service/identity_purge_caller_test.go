package service

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"

	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// TestPurgeIdentityFailsClosedForCallerOnLookupFailure: when the target cannot
// be read, a request marked with CallerIdentity is refused, not deleted
// without authorization. The repository points at a database nothing listens
// on, so the lookup fails with an error that is not a not-found.
func TestPurgeIdentityFailsClosedForCallerOnLookupFailure(t *testing.T) {
	t.Parallel()

	sqldb := sql.OpenDB(pgdriver.NewConnector(
		pgdriver.WithDSN("postgres://u:p@127.0.0.1:1/none?sslmode=disable"),
	))
	db := bun.NewDB(sqldb, pgdialect.New())
	t.Cleanup(func() { _ = db.Close() })
	svc := &IdentityService{repo: postgres.NewIdentityRepository(db)}

	ctx := WithCallerIdentity(context.Background(), CallerIdentity{IdentityID: "00000000-0000-0000-0000-000000000001"})
	err := svc.PurgeIdentity(ctx, "00000000-0000-0000-0000-000000000002", "acct", "proj")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrParentIdentityRefused), "marked caller must be refused, got: %v", err)
}
