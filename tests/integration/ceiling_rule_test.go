package integration_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/highflame-ai/zeroid/internal/telemetry"
)

// countUnboundedScope swaps the ceiling-rule counter for one backed by a
// manual reader and returns a function reporting the count per principal_type.
// Safe to mutate shared state: no integration test calls t.Parallel().
func countUnboundedScope(t *testing.T) func() map[string]int64 {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	counter, err := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).
		Meter("test").Int64Counter("zeroid.workload.unbounded_scope")
	require.NoError(t, err)
	orig := telemetry.WorkloadUnboundedScope
	telemetry.WorkloadUnboundedScope = counter
	t.Cleanup(func() { telemetry.WorkloadUnboundedScope = orig })

	return func() map[string]int64 {
		var rm metricdata.ResourceMetrics
		require.NoError(t, reader.Collect(context.Background(), &rm))
		out := map[string]int64{}
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				if sum, ok := m.Data.(metricdata.Sum[int64]); ok {
					for _, dp := range sum.DataPoints {
						root, _ := dp.Attributes.Value(attribute.Key("principal_type"))
						out[root.AsString()] += dp.Value
					}
				}
			}
		}
		return out
	}
}

// TestCeilingRule_GrantsReportUnboundedScopes drives the real grants and checks
// each one reports to the ceiling-rule counter exactly when nothing but the
// requester bounded the scope it named (P1, counted in phase 1).
func TestCeilingRule_GrantsReportUnboundedScopes(t *testing.T) {
	named := []string{"crm:write"}

	t.Run("api_key with no ceiling is counted as a workload", func(t *testing.T) {
		read := countUnboundedScope(t)
		tn := newTenant(t, "")
		tn.apiKeyRoot(t, named)
		assert.Equal(t, map[string]int64{"workload": 1}, read())
	})

	t.Run("client_credentials is bounded by the client's scopes and not counted", func(t *testing.T) {
		read := countUnboundedScope(t)
		tn := newTenant(t, "")
		tn.workloadRoot(t, tn.policy(t, nil), named)
		assert.Empty(t, read())
	})

	t.Run("a broker root naming a scope with no policy ceiling is counted as a user root", func(t *testing.T) {
		read := countUnboundedScope(t)
		tn := newTenant(t, "")
		tn.userRoot(t, named)
		assert.Equal(t, map[string]int64{"user": 1}, read())
	})

	t.Run("a broker root using a server-defined audience profile is not counted", func(t *testing.T) {
		read := countUnboundedScope(t)
		tn := newTenant(t, "")
		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token": "external-principal-assertion",
			"account_id":    tn.account,
			"project_id":    tn.project,
			"user_id":       uid("hrd-cr-user"),
			"audience":      "codeoid",
		}, map[string]string{testTrustedServiceHeader: "trusted-service"})
		require.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()
		assert.Empty(t, read(), "the scopes came from the server's profile, not the caller")
	})

	t.Run("an exchange is bounded by its parent and not counted", func(t *testing.T) {
		tn := newTenant(t, "")
		policyID := tn.policy(t, named)
		root, _ := tn.workloadRoot(t, policyID, named)
		read := countUnboundedScope(t)
		tn.exchange(t, policyID, uid("hrd-cr-x"), named, root)
		assert.Empty(t, read())
	})
}
