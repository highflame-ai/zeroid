package handler

import (
	"context"
	"net/http"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The multi-value list filters are bound by huma from the query string, and
// that binding — not splitCSV — is where repeated params were being dropped.
//
// huma disables `explode` by default for query params. Its non-explode slice
// path is strings.Split(ctx.Query(name), ","), and ctx.Query returns only the
// FIRST occurrence, so ?status=a&status=b bound to ["a"] and the other values
// vanished before any handler code ran. splitCSV's own unit tests pass a
// []string{"a","b"} directly and therefore could never catch it: they assert
// the layer below the break.
//
// These tests drive a real request through huma so both spellings are pinned at
// the layer that actually decodes them. They fail if anyone drops `,explode`
// from the struct tags.

// bindListAgentsInput runs a GET through huma and returns the bound input.
func bindListAgentsInput(t *testing.T, rawQuery string) ListAgentsInput {
	t.Helper()

	var got ListAgentsInput
	_, api := humatest.New(t)
	huma.Register(api, huma.Operation{
		OperationID: "test-list-agents",
		Method:      http.MethodGet,
		Path:        "/agents/registry",
	}, func(_ context.Context, in *ListAgentsInput) (*struct{}, error) {
		got = *in
		return &struct{}{}, nil
	})

	resp := api.Get("/agents/registry?" + rawQuery)
	// An empty output body yields 204; anything >= 300 means huma rejected the
	// query (a 422 validation failure is the shape a bad tag would produce).
	require.Less(t, resp.Code, 300, "request failed (%d): %s", resp.Code, resp.Body.String())

	return got
}

// bindListIdentitiesInput is the sibling surface, kept in lockstep.
func bindListIdentitiesInput(t *testing.T, rawQuery string) ListIdentitiesInput {
	t.Helper()

	var got ListIdentitiesInput
	_, api := humatest.New(t)
	huma.Register(api, huma.Operation{
		OperationID: "test-list-identities",
		Method:      http.MethodGet,
		Path:        "/identities",
	}, func(_ context.Context, in *ListIdentitiesInput) (*struct{}, error) {
		got = *in
		return &struct{}{}, nil
	})

	resp := api.Get("/identities?" + rawQuery)
	// An empty output body yields 204; anything >= 300 means huma rejected the
	// query (a 422 validation failure is the shape a bad tag would produce).
	require.Less(t, resp.Code, 300, "request failed (%d): %s", resp.Code, resp.Body.String())

	return got
}

func TestListAgentsInput_RepeatedStatusBindsEveryValue(t *testing.T) {
	// The exact shape Studio's inventory sends on every page load. Before
	// `,explode` this bound to ["active"], so the inventory silently filtered to
	// active-only and pending/expired agents were invisible (studio#1405).
	in := bindListAgentsInput(t, "status=active&status=pending&status=expired")
	assert.Equal(t, []string{"active", "pending", "expired"}, splitCSV(in.Status))
}

func TestListAgentsInput_CommaSeparatedStatusStillBinds(t *testing.T) {
	// The documented spelling must keep working — `,explode` changes how huma
	// collects occurrences, and splitCSV is what keeps the comma form valid.
	in := bindListAgentsInput(t, "status=active,pending,expired")
	assert.Equal(t, []string{"active", "pending", "expired"}, splitCSV(in.Status))
}

func TestListAgentsInput_BothSpellingsAgree(t *testing.T) {
	repeated := bindListAgentsInput(t, "status=active&status=pending")
	comma := bindListAgentsInput(t, "status=active,pending")
	assert.Equal(t, splitCSV(comma.Status), splitCSV(repeated.Status))
}

func TestListAgentsInput_RepeatedIdentityTypeAndTrustLevelBind(t *testing.T) {
	// These work today only because Studio happens to comma-join them. Pin the
	// repeated form too, so switching a caller's spelling can't silently narrow
	// the filter the way status did.
	in := bindListAgentsInput(t,
		"identity_type=agent&identity_type=application&trust_level=unverified&trust_level=first_party")
	assert.Equal(t, []string{"agent", "application"}, splitCSV(in.IdentityType))
	assert.Equal(t, []string{"unverified", "first_party"}, splitCSV(in.TrustLevel))
}

func TestListAgentsInput_MixedRepeatedAndCommaBinds(t *testing.T) {
	in := bindListAgentsInput(t, "status=active,pending&status=expired")
	assert.Equal(t, []string{"active", "pending", "expired"}, splitCSV(in.Status))
}

func TestListAgentsInput_SingleValueAndAbsentFilterUnchanged(t *testing.T) {
	in := bindListAgentsInput(t, "status=discovered")
	assert.Equal(t, []string{"discovered"}, splitCSV(in.Status))

	// The adoption inbox sends exactly one status; absent filters must stay nil
	// so the repo applies its default "exclude discovered" branch.
	none := bindListAgentsInput(t, "limit=20")
	assert.Nil(t, splitCSV(none.Status))
	assert.Nil(t, splitCSV(none.IdentityType))
	assert.Nil(t, splitCSV(none.TrustLevel))
}

func TestListAgentsInput_ScalarFiltersUnaffected(t *testing.T) {
	// origin is a single string by contract; adding explode to its neighbours
	// must not disturb it or the pagination params.
	in := bindListAgentsInput(t, "origin=okta&search=bot&limit=50&offset=100")
	assert.Equal(t, "okta", in.Origin)
	assert.Equal(t, "bot", in.Search)
	assert.Equal(t, 50, in.Limit)
	assert.Equal(t, 100, in.Offset)
}

func TestListIdentitiesInput_RepeatedFiltersBindEveryValue(t *testing.T) {
	in := bindListIdentitiesInput(t,
		"status=discovered&status=pending&identity_type=agent&identity_type=mcp_server")
	assert.Equal(t, []string{"discovered", "pending"}, splitCSV(in.Status))
	assert.Equal(t, []string{"agent", "mcp_server"}, splitCSV(in.IdentityType))
}

func TestListIdentitiesInput_CommaSeparatedStillBinds(t *testing.T) {
	in := bindListIdentitiesInput(t, "status=discovered,pending")
	assert.Equal(t, []string{"discovered", "pending"}, splitCSV(in.Status))
}
