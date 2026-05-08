package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// WaitOptions configures WaitForReachable.
type WaitOptions struct {
	// Budget is the total time we'll wait for the dependency to start
	// accepting connections before giving up. Default 60s — long enough
	// to absorb a kind/CI cluster bootstrap, short enough that a genuine
	// misconfig surfaces in under a minute.
	Budget time.Duration

	// InitialBackoff is the delay before the first retry. Default 500ms.
	InitialBackoff time.Duration

	// MaxBackoff caps each individual retry delay. Default 5s. Without
	// the cap exponential growth would put a 30s gap between attempts
	// late in the budget; capping keeps the retry cadence responsive.
	MaxBackoff time.Duration

	// AttemptTimeout caps each ping. Default 5s. A hung TCP connect
	// would otherwise burn the whole budget on a single attempt.
	AttemptTimeout time.Duration
}

func (o WaitOptions) withDefaults() WaitOptions {
	if o.Budget == 0 {
		o.Budget = 60 * time.Second
	}
	if o.InitialBackoff == 0 {
		o.InitialBackoff = 500 * time.Millisecond
	}
	if o.MaxBackoff == 0 {
		o.MaxBackoff = 5 * time.Second
	}
	if o.AttemptTimeout == 0 {
		o.AttemptTimeout = 5 * time.Second
	}
	return o
}

// waitForPing calls ping with bounded exponential backoff until it succeeds
// or the budget runs out. It exists to absorb cross-service startup races —
// services often start in parallel and the dependency (postgres, clickhouse,
// authn JWKS, ...) hasn't bound its port yet when we first try to connect.
//
// Genuine misconfig (wrong DSN, bad credentials, unreachable host) still
// surfaces — the budget is the safety valve. After Budget elapsed, the
// last error is returned and the caller can fatal-quit with a clean cause.
//
// This is the underlying primitive; most callers want WaitForReachable
// which binds it to *sql.DB.PingContext.
func waitForPing(ctx context.Context, ping func(context.Context) error, opts WaitOptions) error {
	opts = opts.withDefaults()

	deadline := time.Now().Add(opts.Budget)
	waitCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	backoff := opts.InitialBackoff
	var lastErr error
	for attempt := 1; ; attempt++ {
		// Per-attempt timeout so a hung connect can't burn the whole budget.
		pingCtx, pingCancel := context.WithTimeout(waitCtx, opts.AttemptTimeout)
		err := ping(pingCtx)
		pingCancel()
		if err == nil {
			if attempt > 1 {
				log.Info().Int("attempts", attempt).Msg("dependency reachable, proceeding")
			}
			return nil
		}
		lastErr = err

		// If the parent context is already done (or budget is up), stop.
		if waitCtx.Err() != nil {
			return fmt.Errorf("dependency not reachable after %d attempts within %s: %w",
				attempt, opts.Budget, lastErr)
		}

		log.Warn().
			Err(err).
			Int("attempt", attempt).
			Dur("next_retry", backoff).
			Msg("dependency not yet reachable, retrying")

		// time.NewTimer + Stop (not time.After) so we don't leak the
		// underlying timer when waitCtx fires before the backoff elapses.
		t := time.NewTimer(backoff)
		select {
		case <-waitCtx.Done():
			t.Stop()
			// Distinguish "we ran out of budget" from "caller cancelled us"
			// for a clearer fatal log line at the call site.
			if errors.Is(waitCtx.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("dependency not reachable after %d attempts within %s: %w",
					attempt, opts.Budget, lastErr)
			}
			return fmt.Errorf("aborted while waiting for dependency: %w", waitCtx.Err())
		case <-t.C:
		}

		backoff *= 2
		if backoff > opts.MaxBackoff {
			backoff = opts.MaxBackoff
		}
	}
}

// WaitForReachable pings db with bounded exponential backoff until it
// succeeds or the budget runs out. See waitForPing for the underlying
// semantics.
func WaitForReachable(ctx context.Context, db *sql.DB, opts WaitOptions) error {
	return waitForPing(ctx, db.PingContext, opts)
}
