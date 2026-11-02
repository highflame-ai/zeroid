package postgres

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"

	"github.com/highflame-ai/zeroid/domain"
)

// noConn is a connector that never connects: the queries below are rendered
// by bun and handed to a hook before any connection is asked for.
type noConn struct{}

func (noConn) Connect(context.Context) (driver.Conn, error) {
	return nil, errors.New("no database in this test")
}
func (noConn) Driver() driver.Driver { return nil }

// capturedSQL returns a bun DB that records each statement it is asked to run.
func capturedSQL() (*bun.DB, *[]string) {
	db := bun.NewDB(sql.OpenDB(noConn{}), pgdialect.New())
	var got []string
	db.AddQueryHook(captureHook{&got})
	return db, &got
}

type captureHook struct{ got *[]string }

func (h captureHook) BeforeQuery(ctx context.Context, e *bun.QueryEvent) context.Context {
	*h.got = append(*h.got, e.Query)
	return ctx
}
func (captureHook) AfterQuery(context.Context, *bun.QueryEvent) {}

// A read-back of RETURNING * fails to scan as soon as the table has a column
// the model lacks (#470). Every write-and-read-back must name the model's
// columns instead.
func TestWritesReturnModelColumnsNotStar(t *testing.T) {
	ctx := context.Background()
	db, got := capturedSQL()

	issuers := NewExternalIssuerRepository(db)
	issuer := &domain.ExternalIssuer{ID: "i1", AccountID: "a1"}
	binding := &domain.IssuerBinding{ID: "b1", AccountID: "a1"}

	cases := []struct {
		name string
		run  func()
	}{
		{"identity deactivate", func() { _, _, _ = NewIdentityRepository(db).DeactivateIfActive(ctx, "id", "a1", "p1") }},
		{"tenant settings upsert", func() {
			_ = NewTenantSettingsRepository(db).UpsertTokenProfile(ctx, &domain.TenantSettings{AccountID: "a1"})
		}},
		{"attestation policy upsert", func() {
			_ = NewAttestationPolicyRepository(db).Upsert(ctx, &domain.AttestationPolicy{AccountID: "a1"}, true)
		}},
		{"issuer insert", func() { _ = issuers.Insert(ctx, issuer) }},
		{"issuer update", func() { _ = issuers.Update(ctx, issuer) }},
		{"issuer set jwks uri", func() { _ = issuers.SetJWKSURI(ctx, issuer) }},
		{"binding insert", func() { _ = issuers.InsertBinding(ctx, binding) }},
		{"binding update", func() { _ = issuers.UpdateBinding(ctx, binding, false) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			*got = nil
			tc.run()
			if len(*got) != 1 {
				t.Fatalf("want 1 statement, got %d: %q", len(*got), *got)
			}
			q := (*got)[0]
			if !strings.Contains(q, "RETURNING") {
				t.Fatalf("expected a RETURNING clause: %s", q)
			}
			if strings.Contains(q, "RETURNING *") {
				t.Errorf("RETURNING * breaks on a column the model lacks: %s", q)
			}
		})
	}
}
