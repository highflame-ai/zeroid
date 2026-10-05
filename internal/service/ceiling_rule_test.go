package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/telemetry"
)

// captureUnboundedScope swaps the ceiling-rule counter for one backed by a
// manual reader and returns a function reporting the counted total and the
// principal_type attribute of each data point.
func captureUnboundedScope(t *testing.T) func() (int64, []string) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	counter, err := mp.Meter("test").Int64Counter("zeroid.workload.unbounded_scope")
	require.NoError(t, err)
	orig := telemetry.WorkloadUnboundedScope
	telemetry.WorkloadUnboundedScope = counter
	t.Cleanup(func() { telemetry.WorkloadUnboundedScope = orig })

	return func() (int64, []string) {
		var rm metricdata.ResourceMetrics
		require.NoError(t, reader.Collect(context.Background(), &rm))
		var total int64
		var roots []string
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				sum, ok := m.Data.(metricdata.Sum[int64])
				if !ok {
					continue
				}
				for _, dp := range sum.DataPoints {
					total += dp.Value
					if v, ok := dp.Attributes.Value(attribute.Key("principal_type")); ok {
						roots = append(roots, v.AsString())
					}
				}
			}
		}
		return total, roots
	}
}

// TestCeilingRule_CountsUnboundedNamedScopes covers the ceiling rule's first
// phase (P1): count, never refuse, a token for a named scope that nothing
// other than the requester bounded — so owners see which agents enforcement
// will break before it does.
func TestCeilingRule_CountsUnboundedNamedScopes(t *testing.T) {
	identity := &domain.Identity{ID: "id-1", AccountID: "acct", ProjectID: "proj"}
	workload := resolvedPrincipal{Type: domain.PrincipalWorkload}
	user := resolvedPrincipal{Type: domain.PrincipalUser}
	named := []string{"crm:write"}

	for _, tc := range []struct {
		name      string
		req       IssueRequest
		principal resolvedPrincipal
		policy    *domain.CredentialPolicy
		wantRoot  string // "" = not counted
	}{
		{"workload with no ceiling naming a scope", IssueRequest{Scopes: named, ScopeCeilingUnbounded: true}, workload, nil, "workload"},
		{"workload with no ceiling naming nothing", IssueRequest{ScopeCeilingUnbounded: true}, workload, nil, ""},
		{"workload with a ceiling", IssueRequest{Scopes: named}, workload, nil, ""},
		{"request-bounded user root, no policy ceiling", IssueRequest{Scopes: named, RequestBoundedRoot: true}, user, &domain.CredentialPolicy{}, "user"},
		{"request-bounded user root, allowed_scopes set", IssueRequest{Scopes: named, RequestBoundedRoot: true}, user, &domain.CredentialPolicy{AllowedScopes: named}, ""},
		{"request-bounded user root, user_grant_scopes set", IssueRequest{Scopes: named, RequestBoundedRoot: true}, user, &domain.CredentialPolicy{UserGrantScopes: named}, ""},
		{"the workload rule does not apply to a user", IssueRequest{Scopes: named, ScopeCeilingUnbounded: true}, user, nil, ""},
		{"the root rule does not apply to a workload", IssueRequest{Scopes: named, RequestBoundedRoot: true}, workload, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			read := captureUnboundedScope(t)
			tc.req.Identity = identity
			(&CredentialService{}).recordUnboundedScope(context.Background(), tc.req, tc.principal, tc.policy)
			total, roots := read()
			if tc.wantRoot == "" {
				assert.Zero(t, total)
				return
			}
			assert.Equal(t, int64(1), total)
			assert.Equal(t, []string{tc.wantRoot}, roots)
		})
	}
}
