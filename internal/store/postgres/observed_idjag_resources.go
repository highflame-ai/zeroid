package postgres

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/uptrace/bun"
)

// maxObservedResourceLen bounds what we will store, matching the column width in
// migration 040. A `resource` claim is an absolute URI naming an MCP server; one
// longer than this is not a real endpoint identifier, and silently truncating it
// would corrupt the inventory (two distinct servers could collapse to one row).
// Over-length values are dropped by Record instead.
const maxObservedResourceLen = 2048

// observedIDJAGResourceRow is the bun model for observed_idjag_resources. Schema
// is defined in migrations/040_observed_idjag_resources.up.sql; this struct must
// stay in sync with the column definitions there.
type observedIDJAGResourceRow struct {
	bun.BaseModel  `bun:"table:observed_idjag_resources"`
	AccountID      string    `bun:"account_id,pk"`
	ProjectID      string    `bun:"project_id,pk"`
	Resource       string    `bun:"resource,pk"`
	AuthorizingISS string    `bun:"authorizing_iss"`
	FirstSeenAt    time.Time `bun:"first_seen_at"`
	LastSeenAt     time.Time `bun:"last_seen_at"`
}

// ObservedIDJAGResource is one MCP server this tenant's agents have actually
// reached through enterprise-managed authorization.
type ObservedIDJAGResource struct {
	Resource       string    `json:"resource"`
	AuthorizingISS string    `json:"authorizing_iss"`
	FirstSeenAt    time.Time `json:"first_seen_at"`
	LastSeenAt     time.Time `json:"last_seen_at"`
}

// ObservedIDJAGResourceStore records the MCP servers named by the `resource`
// claim of successfully-redeemed ID-JAGs (zeroid#259).
//
// One row per (tenant, resource) — deliberately NOT per exchange. Resources are
// a small, slow-moving set (one per MCP endpoint); a tenant redeeming thousands
// of ID-JAGs a day against three servers holds three rows. This is an inventory,
// not a log, and it must not be allowed to become one.
type ObservedIDJAGResourceStore struct {
	db *bun.DB
}

// NewObservedIDJAGResourceStore wires a store against the given bun.DB. The db
// must have the observed_idjag_resources table available (migration 040).
func NewObservedIDJAGResourceStore(db *bun.DB) *ObservedIDJAGResourceStore {
	return &ObservedIDJAGResourceStore{db: db}
}

// NormalizeResource canonicalizes a `resource` claim so the same MCP server does
// not accumulate several rows.
//
// RFC 8707 resource indicators are absolute URIs, and IdPs are inconsistent about
// two things that carry no semantic weight: host case and a trailing slash on an
// otherwise-empty path. Without normalization "https://MCP.acme.com/" and
// "https://mcp.acme.com" are two servers in the inventory and neither matches a
// discovered app's identifier reliably.
//
// Scheme and host are lowercased (case-insensitive per RFC 3986 §3.1/§3.2.2); a
// lone trailing slash is dropped. Path case, query, and fragment are left ALONE —
// those ARE case-sensitive, and folding them would merge genuinely distinct
// resources. A value that does not parse as an absolute URI is returned trimmed
// but otherwise untouched, so an unexpected shape is recorded faithfully rather
// than mangled.
func NormalizeResource(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}

	u, err := url.Parse(trimmed)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return trimmed
	}

	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	if u.Path == "/" {
		u.Path = ""
	}
	return u.String()
}

// Record upserts the resources observed on one successful ID-JAG exchange,
// bumping last_seen_at for those already known and preserving first_seen_at.
//
// Call ONLY after the exchange has fully succeeded. A rejected exchange must
// never reach here: this table is a tenant-visible inventory of internal
// infrastructure, and writing on the failure path would let anyone who can reach
// /oauth2/token plant entries into it.
//
// Errors are returned for the caller to log, never to fail the exchange on — a
// token that has already been minted must not be withheld because a bookkeeping
// write failed. Empty and over-length resources are skipped rather than stored.
func (s *ObservedIDJAGResourceStore) Record(
	ctx context.Context,
	accountID, projectID, authorizingISS string,
	resources []string,
) error {
	if accountID == "" || projectID == "" {
		return nil
	}

	now := time.Now().UTC()
	rows := make([]*observedIDJAGResourceRow, 0, len(resources))
	seen := make(map[string]struct{}, len(resources))

	for _, raw := range resources {
		resource := NormalizeResource(raw)
		if resource == "" || len(resource) > maxObservedResourceLen {
			continue
		}
		// An RFC 8707 array can legitimately repeat a value after normalization
		// ("https://x/" and "https://x"). Postgres rejects a multi-row upsert
		// that touches the same key twice ("ON CONFLICT DO UPDATE command cannot
		// affect row a second time"), so dedupe before building the batch.
		if _, dup := seen[resource]; dup {
			continue
		}
		seen[resource] = struct{}{}

		rows = append(rows, &observedIDJAGResourceRow{
			AccountID:      accountID,
			ProjectID:      projectID,
			Resource:       resource,
			AuthorizingISS: authorizingISS,
			FirstSeenAt:    now,
			LastSeenAt:     now,
		})
	}

	if len(rows) == 0 {
		return nil
	}

	// first_seen_at is deliberately absent from the SET list: it must survive
	// every subsequent observation, which is what makes "how long has this server
	// been in use?" answerable. authorizing_iss is updated because a resource can
	// legitimately move between issuers, and the latest is the useful one.
	_, err := s.db.NewInsert().
		Model(&rows).
		On("CONFLICT (account_id, project_id, resource) DO UPDATE").
		Set("last_seen_at = EXCLUDED.last_seen_at").
		Set("authorizing_iss = EXCLUDED.authorizing_iss").
		Exec(ctx)
	return err
}

// ObservedResourceStaleAfter is how long a resource may go unseen before it
// drops out of the inventory.
//
// The table has no reaper, and it must not accumulate indefinitely: an IdP that
// mints per-object resource URIs would grow the row count without bound. More
// importantly, this inventory feeds MCP typing downstream — without a cutoff, a
// decommissioned server stays listed forever and discovery keeps typing that app
// as an MCP server off a year-old observation.
//
// 90 days is deliberately generous. This is an inventory of infrastructure, not
// a session log; a server used quarterly is still a real server, and dropping it
// too eagerly would make the inventory flap.
const ObservedResourceStaleAfter = 90 * 24 * time.Hour

// maxObservedResourcesReturned caps one response. Resources are a small,
// slow-moving set, so a tenant at this limit means something is generating
// resource URIs per-object rather than per-server — a bounded, wrong answer that
// still renders beats an unbounded one that times out.
const maxObservedResourcesReturned = 500

// List returns the resources observed for a tenant, most recently seen first,
// excluding any not seen within ObservedResourceStaleAfter.
//
// Scoped to (accountID, projectID) with no cross-tenant escape: this is an
// inventory of a customer's internal infrastructure, so a leak here is worse
// than the deployer-configured issuer list. The ordering and cutoff are both
// served by idx_observed_idjag_resources_tenant_last_seen.
func (s *ObservedIDJAGResourceStore) List(
	ctx context.Context,
	accountID, projectID string,
) ([]ObservedIDJAGResource, error) {
	var rows []observedIDJAGResourceRow
	err := s.db.NewSelect().
		Model(&rows).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Where("last_seen_at >= ?", time.Now().UTC().Add(-ObservedResourceStaleAfter)).
		Order("last_seen_at DESC").
		Limit(maxObservedResourcesReturned).
		Scan(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]ObservedIDJAGResource, 0, len(rows))
	for _, r := range rows {
		out = append(out, ObservedIDJAGResource{
			Resource:       r.Resource,
			AuthorizingISS: r.AuthorizingISS,
			FirstSeenAt:    r.FirstSeenAt,
			LastSeenAt:     r.LastSeenAt,
		})
	}
	return out, nil
}
