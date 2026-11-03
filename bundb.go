package zeroid

import (
	"database/sql"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
)

// newBunDB wraps sqldb in a bun.DB for Postgres.
//
// WithDiscardUnknownColumns makes every scan skip columns the Go model does
// not have, instead of failing with "bun: X does not have column Y". Without
// it, any extra column on a table (schema drift, an operator-added column, a
// newer schema during a rolling deploy) breaks every RETURNING * write and
// every raw x.* select that reads that table.
func newBunDB(sqldb *sql.DB) *bun.DB {
	return bun.NewDB(sqldb, pgdialect.New(), bun.WithDiscardUnknownColumns())
}
