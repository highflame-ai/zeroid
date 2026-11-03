package postgres

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"

	"github.com/highflame-ai/zeroid/domain"
)

var errOutsideTx = errors.New("query ran on the repo DB, not the transaction in ctx")

// refuseConnector is the repo's own DB in the test below: any query that
// reaches it ran outside the caller's transaction.
type refuseConnector struct{}

func (refuseConnector) Connect(context.Context) (driver.Conn, error) { return nil, errOutsideTx }
func (refuseConnector) Driver() driver.Driver                        { return nil }

// txConnector backs the caller's transaction. It answers every statement
// with no rows and counts the statements it saw.
type txConnector struct {
	mu      sync.Mutex
	queries int
}

func (c *txConnector) Connect(context.Context) (driver.Conn, error) { return &txConn{c: c}, nil }
func (c *txConnector) Driver() driver.Driver                        { return nil }

func (c *txConnector) seen() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.queries
}

type txConn struct{ c *txConnector }

func (*txConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not supported") }
func (*txConn) Close() error                        { return nil }
func (*txConn) Begin() (driver.Tx, error)           { return fakeTx{}, nil }

func (*txConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) { return fakeTx{}, nil }

func (t *txConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	t.c.mu.Lock()
	t.c.queries++
	t.c.mu.Unlock()
	return emptyRows{}, nil
}

func (t *txConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	t.c.mu.Lock()
	t.c.queries++
	t.c.mu.Unlock()
	return driver.RowsAffected(0), nil
}

type fakeTx struct{}

func (fakeTx) Commit() error   { return nil }
func (fakeTx) Rollback() error { return nil }

type emptyRows struct{}

func (emptyRows) Columns() []string         { return []string{"id"} }
func (emptyRows) Close() error              { return nil }
func (emptyRows) Next([]driver.Value) error { return io.EOF }

// TestAttestationPolicyRepository_UsesTxFromContext pins that every method
// runs on the transaction attached with WithTx. A method that used r.db
// directly would commit on its own even if the outer transaction rolled
// back, and could wait on row locks that transaction holds.
func TestAttestationPolicyRepository_UsesTxFromContext(t *testing.T) {
	repoSQL := sql.OpenDB(refuseConnector{})
	t.Cleanup(func() { _ = repoSQL.Close() })
	repo := NewAttestationPolicyRepository(bun.NewDB(repoSQL, pgdialect.New()))

	conn := &txConnector{}
	txSQL := sql.OpenDB(conn)
	t.Cleanup(func() { _ = txSQL.Close() })
	txDB := bun.NewDB(txSQL, pgdialect.New())

	calls := map[string]func(ctx context.Context) error{
		"GetByTenantProofType": func(ctx context.Context) error {
			_, err := repo.GetByTenantProofType(ctx, "acct", "proj", domain.ProofTypeOIDCToken)
			return err
		},
		"Upsert": func(ctx context.Context) error {
			return repo.Upsert(ctx, &domain.AttestationPolicy{AccountID: "acct", ProjectID: "proj"}, true)
		},
		"List": func(ctx context.Context) error {
			_, err := repo.List(ctx, "acct", "proj")
			return err
		},
		"Delete": func(ctx context.Context) error {
			return repo.Delete(ctx, "id", "acct", "proj")
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			before := conn.seen()
			err := txDB.RunInTx(context.Background(), nil, func(ctx context.Context, tx bun.Tx) error {
				err := call(WithTx(ctx, tx))
				assert.NotErrorIs(t, err, errOutsideTx)
				return nil
			})
			require.NoError(t, err)
			assert.Greater(t, conn.seen(), before, "%s did not run on the transaction", name)
		})
	}
}
