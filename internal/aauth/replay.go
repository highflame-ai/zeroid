package aauth

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/uptrace/bun"
)

// redemptions records which agent key redeemed each workload assertion at
// POST /ap/token (migration 069). The assertion is spent once, in the shared
// single-use store; this adds the key it was bound to, so the same key may
// redeem it again and any other key is refused.
//
// Repeats are for a Kubernetes pod, whose projected token can't be re-minted
// on demand and is shared by every worker and restarted container of the pod.
// That works because the pod keeps ONE agent key for its life, in a file every
// container mounts (an emptyDir): the SDK reads it rather than generating a
// key per process. A process that does generate a new key is a different key,
// and has to wait for the kubelet's next token, as it would at the token
// endpoint. No transaction is needed:
//
//  1. claim inserts (key, jkt, minted=false) if the key is new. The primary
//     key decides between racing redeemers.
//  2. A fresh claim spends the assertion in the shared store. If that store
//     says it was already spent (at the token endpoint), the claim stays
//     unminted and every later redemption is refused.
//  3. After a successful mint, confirm sets minted=true. Only then may the
//     same key redeem again, so a refusal (no binding, an inactive identity, a
//     policy) can't be replayed for its events.
//  4. A server-side failure forgets the claim and releases the spend, so a
//     retry with the same platform token works.
type redemptions struct {
	db *bun.DB
}

type claimResult int

const (
	// claimFresh: this request is the first to redeem the assertion.
	claimFresh claimResult = iota
	// claimRepeat: the same key redeemed it before, and minted.
	claimRepeat
	// claimRefused: another key holds it.
	claimRefused
	// claimPending: this key claimed it, and has not minted: the first
	// request is still in flight, or was refused.
	claimPending
)

// pendingInFlight is how long after a claim an unminted redemption by the same
// key is taken to be still in flight rather than refused.
const pendingInFlight = 30 * time.Second

// claim returns the result, and for claimPending how long ago the claim was
// made.
func (s *redemptions) claim(ctx context.Context, replayKey, jkt string, expiresAt time.Time) (claimResult, time.Duration, error) {
	res, err := s.db.NewRaw(
		`INSERT INTO aauth_bootstrap_redemptions (replay_key, jkt, expires_at) VALUES (?, ?, ?)
		 ON CONFLICT (replay_key) DO NOTHING`, replayKey, jkt, expiresAt).Exec(ctx)
	if err != nil {
		return claimRefused, 0, err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return claimFresh, 0, nil
	}
	var row struct {
		JKT    string        `bun:"jkt"`
		Minted bool          `bun:"minted"`
		Age    time.Duration `bun:"age"`
	}
	err = s.db.NewRaw(`SELECT jkt, minted, (EXTRACT(EPOCH FROM NOW() - created_at) * 1000000000)::bigint AS age
		FROM aauth_bootstrap_redemptions WHERE replay_key = ?`, replayKey).Scan(ctx, &row)
	if errors.Is(err, sql.ErrNoRows) {
		// Swept between the insert and the read: the assertion has expired.
		return claimRefused, 0, nil
	}
	if err != nil {
		return claimRefused, 0, err
	}
	switch {
	case row.JKT != jkt:
		return claimRefused, 0, nil
	case row.Minted:
		return claimRepeat, 0, nil
	default:
		return claimPending, row.Age, nil
	}
}

func (s *redemptions) confirm(ctx context.Context, replayKey string) error {
	_, err := s.db.NewRaw(`UPDATE aauth_bootstrap_redemptions SET minted = TRUE WHERE replay_key = ?`, replayKey).Exec(ctx)
	return err
}

// forget drops a claim that never minted, after a server-side failure.
func (s *redemptions) forget(ctx context.Context, replayKey string) error {
	_, err := s.db.NewRaw(`DELETE FROM aauth_bootstrap_redemptions WHERE replay_key = ? AND NOT minted`, replayKey).Exec(ctx)
	return err
}
