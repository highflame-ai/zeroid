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
//
// Nesting: calling WithTx on a context that already carries a tx
// REPLACES the parent tx for any descendant ctx — there is no automatic
// savepoint or merge. Postgres doesn't support truly nested transactions
// anyway, and bun.RunInTx returns the existing tx when called recursively.
// For most flows the right pattern is "open one tx at the outermost
// service call, attach it once, do all the work inside" — don't nest.
func WithTx(ctx context.Context, tx bun.Tx) context.Context {
	return context.WithValue(ctx, txKey{}, tx)
}

// txFromContext extracts the in-flight transaction attached by WithTx.
// Returns the tx and true when one is set; the zero bun.Tx and false
// otherwise. Used as the shared core of dbOrTx and hasTx so the
// type-assertion key and shape live in exactly one place.
func txFromContext(ctx context.Context) (bun.Tx, bool) {
	tx, ok := ctx.Value(txKey{}).(bun.Tx)
	return tx, ok
}

// dbOrTx returns the in-flight transaction from ctx if one is set, falling
// back to the repo's default DB handle. Repo methods that participate in
// transactions call this once at the top and use the returned bun.IDB for
// every statement in the method.
func dbOrTx(ctx context.Context, fallback bun.IDB) bun.IDB {
	if tx, ok := txFromContext(ctx); ok {
		return tx
	}
	return fallback
}

// hasTx reports whether ctx carries an in-flight transaction attached
// with WithTx. Repo methods that ONLY make sense inside a transaction
// (e.g., SELECT ... FOR UPDATE callers) use this to fail fast on misuse
// instead of silently downgrading to a per-statement implicit tx.
func hasTx(ctx context.Context) bool {
	_, ok := txFromContext(ctx)
	return ok
}
