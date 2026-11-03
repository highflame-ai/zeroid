package zeroid

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
)

// driftConnector is a database/sql driver that answers every query with one
// row carrying a column the model below does not have, as a table with
// schema drift would.
type driftConnector struct{}

func (driftConnector) Connect(context.Context) (driver.Conn, error) { return driftConn{}, nil }
func (driftConnector) Driver() driver.Driver                        { return nil }

type driftConn struct{}

func (driftConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not supported") }
func (driftConn) Close() error                        { return nil }
func (driftConn) Begin() (driver.Tx, error)           { return nil, errors.New("not supported") }

func (driftConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return &driftRows{}, nil
}

type driftRows struct{ done bool }

func (*driftRows) Columns() []string { return []string{"id", "drift_extra"} }
func (*driftRows) Close() error      { return nil }

func (r *driftRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = "id-1"
	dest[1] = "unknown"
	return nil
}

type driftModel struct {
	ID string `bun:"id"`
}

func openDriftDB(t *testing.T) *sql.DB {
	t.Helper()
	sqldb := sql.OpenDB(driftConnector{})
	t.Cleanup(func() { _ = sqldb.Close() })
	return sqldb
}

// TestNewBunDB_DiscardsUnknownColumns pins that the DB handle zeroid builds
// tolerates a column the model lacks, so RETURNING * writes and raw x.*
// selects keep working when a table has an extra column.
func TestNewBunDB_DiscardsUnknownColumns(t *testing.T) {
	ctx := context.Background()

	// Control: a plain bun.DB rejects the extra column. If this ever passes,
	// the driver above no longer reproduces the drift and the test is moot.
	plain := bun.NewDB(openDriftDB(t), pgdialect.New())
	var m driftModel
	err := plain.NewRaw("SELECT 1").Scan(ctx, &m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "drift_extra")

	db := newBunDB(openDriftDB(t))
	var got driftModel
	require.NoError(t, db.NewRaw("SELECT 1").Scan(ctx, &got))
	assert.Equal(t, "id-1", got.ID)
}
