package integration_test

// A cascade revocation that PostgreSQL aborts as a deadlock victim (40P01) or
// a serialization failure (40001) is run again, and a revocation that fails
// is never reported as done.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun/driver/pgdriver"

	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// rtFailUpdates makes every UPDATE of the credentials whose subject is
// subject fail with SQLSTATE code, the first times attempts (every attempt
// when times is negative). It returns a func reporting how many UPDATEs were
// attempted. Each test uses a subject of its own, so no other row is touched.
func rtFailUpdates(t *testing.T, subject, code string, times int) (attempts func() int) {
	t.Helper()
	ctx := context.Background()
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	seq, trigger := "rt_seq_"+suffix, "rt_fail_"+suffix
	_, err := testDB.ExecContext(ctx, `
		CREATE OR REPLACE FUNCTION rt_fail_update() RETURNS trigger AS $$
		BEGIN
			IF nextval(TG_ARGV[1]::regclass) <= TG_ARGV[2]::bigint OR TG_ARGV[2]::bigint < 0 THEN
				RAISE EXCEPTION 'injected failure' USING ERRCODE = TG_ARGV[0];
			END IF;
			RETURN NEW;
		END
		$$ LANGUAGE plpgsql`)
	require.NoError(t, err)
	_, err = testDB.ExecContext(ctx, `CREATE SEQUENCE `+seq)
	require.NoError(t, err)
	_, err = testDB.ExecContext(ctx, fmt.Sprintf(`
		CREATE TRIGGER %s BEFORE UPDATE ON issued_credentials
		FOR EACH ROW WHEN (OLD.subject = '%s')
		EXECUTE FUNCTION rt_fail_update('%s', '%s', '%d')`, trigger, subject, code, seq, times))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = testDB.ExecContext(ctx, `DROP TRIGGER IF EXISTS `+trigger+` ON issued_credentials`)
		_, _ = testDB.ExecContext(ctx, `DROP SEQUENCE IF EXISTS `+seq)
	})
	return func() int {
		var n struct {
			LastValue int  `bun:"last_value"`
			IsCalled  bool `bun:"is_called"`
		}
		require.NoError(t, testDB.NewRaw(`SELECT last_value, is_called FROM `+seq).Scan(ctx, &n))
		if !n.IsCalled {
			return 0
		}
		return n.LastValue
	}
}

// rtCascades revokes, through each of the three cascades, a token with the
// given subject. Each returns the rows the cascade reported.
var rtCascades = map[string]func(t *testing.T, tn hrdTenant, subject string) (jti string, revoke func() ([]postgres.RevokedCredential, error)){
	"single": func(t *testing.T, tn hrdTenant, subject string) (string, func() ([]postgres.RevokedCredential, error)) {
		id, jti := rlCred(t, tn, "", "", subject)
		return jti, func() ([]postgres.RevokedCredential, error) {
			return postgres.NewCredentialRepository(testDB).Revoke(context.Background(), id, tn.account, tn.project, "retry_test")
		}
	},
	"identity": func(t *testing.T, tn hrdTenant, subject string) (string, func() ([]postgres.RevokedCredential, error)) {
		identityID := rlIdentity(t, tn, tn.policy(t, []string{"data:read"}))
		_, jti := rlCred(t, tn, "", identityID, subject)
		return jti, func() ([]postgres.RevokedCredential, error) {
			return postgres.NewCredentialRepository(testDB).RevokeAllActiveForIdentity(context.Background(), identityID, "retry_test")
		}
	},
	"owner": func(t *testing.T, tn hrdTenant, subject string) (string, func() ([]postgres.RevokedCredential, error)) {
		identityID := rlIdentity(t, tn, tn.policy(t, []string{"data:read"}))
		_, jti := rlCred(t, tn, "", identityID, subject)
		return jti, func() ([]postgres.RevokedCredential, error) {
			return postgres.NewCredentialRepository(testDB).RevokeAllActiveForOwner(context.Background(), "user-test-owner", tn.account, "retry_test")
		}
	},
}

func rtSQLState(err error) string {
	var pgErr pgdriver.Error
	if errors.As(err, &pgErr) {
		return pgErr.Field('C')
	}
	return ""
}

// TestCascadeRevocationRetriesTransientFailure aborts each cascade's UPDATE
// once with a deadlock (40P01) or a serialization failure (40001). The
// cascade MUST be run again and succeed, not hand the abort to its caller,
// which for a CAE signal or a suspension used to log it and carry on with the
// tokens live. A failure of any other kind is returned at once, and a
// transient one that persists is returned after a bounded number of tries.
func TestCascadeRevocationRetriesTransientFailure(t *testing.T) {
	for name, setup := range rtCascades {
		t.Run(name, func(t *testing.T) {
			for _, code := range []string{"40P01", "40001"} {
				t.Run(code+" once", func(t *testing.T) {
					tn := newTenant(t, "")
					subject := uid("rt-once")
					jti, revoke := setup(t, tn, subject)
					attempts := rtFailUpdates(t, subject, code, 1)
					rows, err := revoke()
					require.NoError(t, err, "a cascade aborted once as a %s victim MUST be retried", code)
					assert.Equal(t, 2, attempts())
					require.Len(t, rows, 1)
					assert.Equal(t, jti, rows[0].JTI)
					assert.True(t, rlRowRevoked(t, jti))
				})
			}
			t.Run("40P01 every time", func(t *testing.T) {
				tn := newTenant(t, "")
				subject := uid("rt-always")
				jti, revoke := setup(t, tn, subject)
				attempts := rtFailUpdates(t, subject, "40P01", -1)
				_, err := revoke()
				assert.Equal(t, "40P01", rtSQLState(err), "a deadlock that persists is returned: %v", err)
				assert.Equal(t, postgres.CascadeRevocationAttempts, attempts())
				assert.False(t, rlRowRevoked(t, jti))
			})
			t.Run("other failure", func(t *testing.T) {
				tn := newTenant(t, "")
				subject := uid("rt-other")
				_, revoke := setup(t, tn, subject)
				attempts := rtFailUpdates(t, subject, "P0001", -1)
				_, err := revoke()
				assert.Equal(t, "P0001", rtSQLState(err), "%v", err)
				assert.Equal(t, 1, attempts(), "only a deadlock or a serialization failure is retried")
			})
		})
	}
}

// TestCAESignalReportsFailedAutoRevoke makes the auto-revocation of a
// critical CAE signal fail. The ingest MUST NOT answer as if the identity's
// tokens were revoked: the caller, told 201, would never retry, and every
// token of the identity would stay live.
func TestCAESignalReportsFailedAutoRevoke(t *testing.T) {
	tn := newTenant(t, "")
	identityID := rlIdentity(t, tn, tn.policy(t, []string{"data:read"}))
	subject := uid("rt-cae")
	_, jti := rlCred(t, tn, "", identityID, subject)
	rtFailUpdates(t, subject, "P0001", -1)

	resp := post(t, adminPath("/signals/ingest"), map[string]any{
		"identity_id": identityID,
		"signal_type": "anomalous_behavior",
		"severity":    "critical",
		"source":      "integration-test",
	}, tn.headers)
	body := decode(t, resp)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode,
		"a signal whose auto-revocation failed MUST NOT be reported as handled: %v", body)
	assert.False(t, rlRowRevoked(t, jti), "the injected failure left the token live")
}
