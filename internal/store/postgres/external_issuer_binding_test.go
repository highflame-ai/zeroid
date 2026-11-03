package postgres

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"

	"github.com/highflame-ai/zeroid/domain"
)

// bindingConnector stands in for Postgres in the UpdateBinding test: the
// conditional UPDATE matches no row, and the follow-up existence check
// answers exists.
type bindingConnector struct{ exists bool }

func (c bindingConnector) Connect(context.Context) (driver.Conn, error) {
	return bindingConn(c), nil
}
func (bindingConnector) Driver() driver.Driver { return nil }

type bindingConn struct{ exists bool }

func (bindingConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not supported") }
func (bindingConn) Close() error                        { return nil }
func (bindingConn) Begin() (driver.Tx, error)           { return nil, errors.New("not supported") }

func (c bindingConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "EXISTS") {
		return &bindingRows{cols: []string{"exists"}, row: []driver.Value{c.exists}}, nil
	}
	return &bindingRows{cols: []string{"id"}}, nil // UPDATE ... RETURNING: no row matched
}

func (bindingConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return driver.RowsAffected(0), nil
}

type bindingRows struct {
	cols []string
	row  []driver.Value
}

func (r *bindingRows) Columns() []string { return r.cols }
func (*bindingRows) Close() error        { return nil }

func (r *bindingRows) Next(dest []driver.Value) error {
	if r.row == nil {
		return io.EOF
	}
	copy(dest, r.row)
	r.row = nil
	return nil
}

// TestUpdateBinding_ConditionalMissReportsNotFound pins that a conditional
// enable which matches no row reports a policy refusal only when the
// binding still exists. A binding that is gone (never existed, soft-deleted
// concurrently, another account's) must come back as sql.ErrNoRows, so the
// caller answers 404 instead of binding_explicitly_disabled.
func TestUpdateBinding_ConditionalMissReportsNotFound(t *testing.T) {
	for _, tc := range []struct {
		name   string
		exists bool
		want   error
	}{
		{name: "binding exists, so it is explicitly disabled", exists: true, want: ErrBindingExplicitlyDisabled},
		{name: "binding is gone", exists: false, want: sql.ErrNoRows},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sqldb := sql.OpenDB(bindingConnector{exists: tc.exists})
			t.Cleanup(func() { _ = sqldb.Close() })
			repo := NewExternalIssuerRepository(bun.NewDB(sqldb, pgdialect.New()))

			b := &domain.IssuerBinding{ID: "b1", AccountID: "acct", Enabled: true}
			err := repo.UpdateBinding(context.Background(), b, true)
			assert.ErrorIs(t, err, tc.want)
		})
	}
}
