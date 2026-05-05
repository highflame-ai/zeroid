package postgres

import (
	"context"

	"github.com/uptrace/bun"
)

// txKey is the context-value key for an in-flight transaction. Unexported
// + struct{}-typed so external packages can't collide with us in the same
// context tree.
type txKey struct{}

// WithTx attaches a transaction to ctx. Repo methods that call
// dbOrTx pick the transaction up automatically. Use this together with
// bun.DB.RunInTx in services that need to coordinate writes across multiple
// repos atomically:
//
//	err := s.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
//	    ctx = postgres.WithTx(ctx, tx)
//	    if err := s.fooRepo.Create(ctx, foo); err != nil { return err }
//	    if err := s.barRepo.Update(ctx, bar); err != nil { return err }
//	    return nil
//	})
//
// Repo callers that don't open a transaction get the repo's own *bun.DB
// handle and behave as before (auto-commit per statement).
func WithTx(ctx context.Context, tx bun.Tx) context.Context {
	return context.WithValue(ctx, txKey{}, tx)
}

// dbOrTx returns the in-flight transaction from ctx if one is set, falling
// back to the repo's default DB handle. Repo methods that participate in
// transactions call this once at the top and use the returned bun.IDB for
// every statement in the method.
func dbOrTx(ctx context.Context, fallback bun.IDB) bun.IDB {
	if tx, ok := ctx.Value(txKey{}).(bun.Tx); ok {
		return tx
	}
	return fallback
}
