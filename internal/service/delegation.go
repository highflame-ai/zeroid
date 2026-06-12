package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// ErrCredentialNotFound is returned by WalkByJTI when no credential
// matches the requested JTI within the caller's tenant scope. Handlers
// map this to 404; any other error maps to 500.
var ErrCredentialNotFound = errors.New("credential not found")

// MaxGraphDepth caps the recursive CTE depth on /delegations/graph
// regardless of what the caller requests. The recursive CTE itself uses
// this cap as the depth guard inside the SQL WITH clause; exporting it
// here lets handlers reject requests outside the supported range early.
const MaxGraphDepth = 10

// MaxGraphNodes caps the size of a /delegations/graph response. When
// exceeded the response carries Truncated=true so the consumer knows the
// view is incomplete. Picked to match the snappy-with-up-to-500-nodes
// acceptance target on issue #153.
const MaxGraphNodes = 500

// GraphNode is a single identity rendered in the delegation graph.
// Stripped to the fields a force-graph or list view needs — full
// identity records are available via /identities/{id}.
type GraphNode struct {
	ID           string `json:"id"`
	WIMSEURI     string `json:"wimse_uri"`
	Name         string `json:"name"`
	IdentityType string `json:"identity_type"`
	TrustLevel   string `json:"trust_level"`
	Status       string `json:"status"`
}

// GraphEdge is one delegation hop — an issued credential connecting two
// identities. ScopesIn/ScopesOut/Attenuated are the scope-attenuation
// triple; for root credentials (no parent) ScopesIn equals ScopesOut and
// Attenuated is empty.
//
// RevokedAt and RevokeReason surface the durable audit fields from the
// underlying credential row — populated only when IsRevoked is true so
// downstream UIs can render "revoked at T by reason R" without a second
// round-trip to the credential repository. Both are omitempty so the wire
// shape stays unchanged for unrevoked edges.
type GraphEdge struct {
	From            string     `json:"from,omitempty"`
	To              string     `json:"to,omitempty"`
	JTI             string     `json:"jti"`
	ParentJTI       string     `json:"parent_jti,omitempty"`
	MissionID       string     `json:"mission_id,omitempty"`
	IssuedAt        time.Time  `json:"issued_at"`
	ExpiresAt       time.Time  `json:"expires_at"`
	GrantType       string     `json:"grant_type"`
	DelegationDepth int        `json:"delegation_depth"`
	ScopesIn        []string   `json:"scopes_in"`
	ScopesOut       []string   `json:"scopes_out"`
	Attenuated      []string   `json:"attenuated"`
	IsRevoked       bool       `json:"is_revoked"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
	RevokeReason    string     `json:"revoke_reason,omitempty"`
}

// Graph is the response shape for /delegations/graph — a depth-bounded
// local subgraph centered on a focal identity. FocalID is the
// identity_id the request was anchored on. Truncated is set when the
// raw walk would have exceeded MaxGraphNodes.
type Graph struct {
	Nodes     []*GraphNode `json:"nodes"`
	Edges     []*GraphEdge `json:"edges"`
	FocalID   string       `json:"focal_id"`
	Truncated bool         `json:"truncated,omitempty"`
}

// Chain is the response shape for /delegations/by-jti/{jti} — one full
// lineage from root to leaf with scope attenuation per edge.
type Chain struct {
	Nodes []*GraphNode `json:"nodes"`
	Edges []*GraphEdge `json:"edges"`
}

// DelegationService assembles delegation graphs and chains for the
// Delegation Explorer endpoints. It is a thin coordinator over the
// credential repository (already has ListByIdentity), the new
// DelegationRepository (WalkUp / WalkDown / ListChains), and the
// identity repository (GetByIDs for batch node enrichment).
type DelegationService struct {
	credRepo     *postgres.CredentialRepository
	delegRepo    *postgres.DelegationRepository
	identityRepo *postgres.IdentityRepository
}

// NewDelegationService creates a DelegationService.
func NewDelegationService(credRepo *postgres.CredentialRepository, delegRepo *postgres.DelegationRepository, identityRepo *postgres.IdentityRepository) *DelegationService {
	return &DelegationService{
		credRepo:     credRepo,
		delegRepo:    delegRepo,
		identityRepo: identityRepo,
	}
}

// GetGraph returns the full delegation tree for the identity identified
// by identityID. The algorithm walks up from the focal identity's
// credentials to find the root(s) (credentials with no parent_jti),
// then walks down from each root to build the complete tree. The focal
// identity is returned as FocalID so the UI can highlight it.
//
// The up-walk is uncapped (uses maxUpWalkDepth = 100) because it is
// linear — each credential has at most one parent. The down-walk uses
// MaxGraphDepth to bound fan-out. MaxGraphNodes caps the total response.
//
// When the identity has issued no credentials yet, returns a one-node
// graph (just the identity, no edges).
func (s *DelegationService) GetGraph(ctx context.Context, identityID string, _ int, accountID, projectID string) (*Graph, error) {
	creds, err := s.credRepo.ListByIdentity(ctx, identityID, accountID, projectID)
	if err != nil {
		return nil, fmt.Errorf("look up focal identity credentials: %w", err)
	}

	// No credentials yet — return a single-node graph anchored on the
	// identity if it exists. If the identity itself can't be loaded
	// (unknown UUID, or owned by a different tenant) return an empty
	// graph rather than an error: ListByIdentity already enforces
	// tenant scope, so this branch is the natural funnel for both
	// "not yet active" and "not visible to this tenant" — and the
	// caller cannot tell them apart by design.
	if len(creds) == 0 {
		id, err := s.identityRepo.GetByID(ctx, identityID, accountID, projectID)
		if err != nil {
			return &Graph{Nodes: nil, Edges: nil, FocalID: identityID}, nil
		}
		return &Graph{
			Nodes:   []*GraphNode{identityToNode(id)},
			Edges:   nil,
			FocalID: identityID,
		}, nil
	}

	// For each credential, walk up to the root (uncapped — linear chain,
	// negligible cost), then walk the entire tree down from that root.
	// This ensures the graph shows the full tree including siblings and
	// their subtrees, not just the focal identity's direct ancestors and
	// descendants.
	//
	// A single identity may hold multiple independent root credentials
	// (e.g. each Claude Code session issues a fresh client_credentials
	// token). When the focal credential's parent_jti points at one of
	// those roots, the other roots (and their subtrees) would be invisible
	// if we only walked down from the single root we reached. To fix this,
	// after finding a root credential we also list ALL credentials for the
	// root's identity and include them as additional roots.
	//
	// All roots are batched into a single WalkDownMulti call (one CTE
	// seeded with N roots) instead of N separate queries.
	const maxUpWalkDepth = 100 // linear chain, safe to go deep
	walkedRoots := make(map[string]struct{})
	walkedUp := make(map[string]struct{}) // JTIs already used as WalkUp seeds
	var allRoots []string

	for _, c := range creds {
		// Skip credentials already visited by a prior WalkUp — they share
		// the same ancestor chain so walking again is redundant.
		if _, done := walkedUp[c.JTI]; done {
			continue
		}
		walkedUp[c.JTI] = struct{}{}

		// Walk up to find the root credential(s).
		up, err := s.delegRepo.WalkUp(ctx, c.JTI, accountID, projectID, maxUpWalkDepth)
		if err != nil {
			return nil, err
		}

		// Mark all credentials in this chain as visited so we don't
		// re-walk from a sibling credential in the same chain.
		for _, u := range up {
			walkedUp[u.JTI] = struct{}{}
		}

		// Find root credentials — those with no parent_jti.
		roots := findRoots(up)
		if len(roots) == 0 {
			roots = []string{c.JTI}
		}

		// Expand roots: for each root credential, find ALL credentials
		// belonging to the same identity so we also walk down from sibling
		// root credentials. This handles the case where a parent identity
		// has multiple independent root tokens.
		expandedRoots := s.expandRootsByIdentity(ctx, up, roots, accountID, projectID, walkedRoots)

		for _, rootJTI := range expandedRoots {
			if _, ok := walkedRoots[rootJTI]; ok {
				continue
			}
			walkedRoots[rootJTI] = struct{}{}
			allRoots = append(allRoots, rootJTI)
		}
	}

	// Single batched walk-down from all collected roots.
	down, err := s.delegRepo.WalkDownMulti(ctx, allRoots, accountID, projectID, MaxGraphDepth)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(down))
	var all []*domain.IssuedCredential
	for _, item := range down {
		if _, ok := seen[item.JTI]; !ok {
			seen[item.JTI] = struct{}{}
			all = append(all, item)
		}
	}

	graph := s.buildGraph(ctx, all, accountID, projectID, identityID)
	return graph, nil
}

// findRoots returns the JTIs of credentials that have no parent
// (ParentJTI is empty). These are the roots of delegation trees.
func findRoots(creds []*domain.IssuedCredential) []string {
	var roots []string
	for _, c := range creds {
		if c.ParentJTI == "" {
			roots = append(roots, c.JTI)
		}
	}
	return roots
}

// expandRootsByIdentity takes the root JTIs found via WalkUp and expands
// them: for each root credential, it looks up ALL credentials belonging
// to that root's identity and includes any that are also roots (no
// parent_jti). This handles the common case where a parent identity
// holds multiple independent root credentials (e.g. repeated
// client_credentials grants across sessions) and child delegations are
// spread across different root JTIs of the same identity.
//
// The `up` slice is the full WalkUp result (used to find root identity
// IDs without an extra DB call). `seen` is checked to skip identities
// already expanded.
func (s *DelegationService) expandRootsByIdentity(
	ctx context.Context,
	up []*domain.IssuedCredential,
	roots []string,
	accountID, projectID string,
	seen map[string]struct{},
) []string {
	// Index the WalkUp results by JTI to resolve root JTI → identity.
	byJTI := make(map[string]*domain.IssuedCredential, len(up))
	for _, c := range up {
		byJTI[c.JTI] = c
	}

	expanded := make([]string, 0, len(roots))
	expandedIdentities := make(map[string]struct{})

	for _, rootJTI := range roots {
		expanded = append(expanded, rootJTI)

		rootCred, ok := byJTI[rootJTI]
		if !ok || rootCred.IdentityID == nil || *rootCred.IdentityID == "" {
			continue
		}
		identityID := *rootCred.IdentityID
		if _, done := expandedIdentities[identityID]; done {
			continue
		}
		expandedIdentities[identityID] = struct{}{}

		// List all credentials for this identity to find sibling roots.
		siblingCreds, err := s.credRepo.ListByIdentity(ctx, identityID, accountID, projectID)
		if err != nil {
			log.Warn().Err(err).Str("identity_id", identityID).
				Msg("failed to expand root identity credentials; continuing with known roots")
			continue
		}
		for _, sc := range siblingCreds {
			if sc.ParentJTI == "" && sc.JTI != rootJTI {
				if _, already := seen[sc.JTI]; !already {
					expanded = append(expanded, sc.JTI)
				}
			}
		}
	}
	return expanded
}

// WalkByJTI returns the full lineage from root to the credential
// identified by jti. Useful for forensic "show me where this token came
// from" queries — every hop with its scope attenuation.
//
// Walks up to MaxGraphDepth hops; deeper chains are silently truncated
// at the root end (the returned chain still ends at the requested jti).
func (s *DelegationService) WalkByJTI(ctx context.Context, jti, accountID, projectID string) (*Chain, error) {
	creds, err := s.delegRepo.WalkUp(ctx, jti, accountID, projectID, MaxGraphDepth)
	if err != nil {
		return nil, err
	}
	if len(creds) == 0 {
		return nil, ErrCredentialNotFound
	}
	g := s.buildGraph(ctx, creds, accountID, projectID, "")
	return &Chain{Nodes: g.Nodes, Edges: g.Edges}, nil
}

// ListChains returns chain summaries (one per delegation tree) active
// in the [since, until) window, ordered by last activity DESC.
//
// until defaults to now() when zero; since defaults to until - 30 days
// when zero. Limit is clamped to [1, 500].
func (s *DelegationService) ListChains(ctx context.Context, since, until time.Time, limit int, accountID, projectID string) ([]*postgres.ChainSummary, error) {
	if until.IsZero() {
		until = time.Now()
	}
	if since.IsZero() {
		since = until.Add(-30 * 24 * time.Hour)
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	return s.delegRepo.ListChains(ctx, accountID, projectID, since, until, limit)
}

// IdentityDepths returns the maximum delegation depth per identity for the
// given identity IDs. Identities with no credentials are omitted.
func (s *DelegationService) IdentityDepths(ctx context.Context, identityIDs []string, accountID, projectID string) ([]*postgres.IdentityDepth, error) {
	return s.delegRepo.MaxDepthByIdentities(ctx, accountID, projectID, identityIDs)
}

// buildGraph turns a flat ordered credential list into the
// (nodes, edges) shape, computing scope attenuation per edge and
// batch-loading identities. focalID is forwarded onto the returned
// Graph; pass "" when not relevant (e.g. /by-jti responses).
func (s *DelegationService) buildGraph(ctx context.Context, creds []*domain.IssuedCredential, accountID, projectID, focalID string) *Graph {
	truncated := false
	if len(creds) > MaxGraphNodes {
		creds = creds[:MaxGraphNodes]
		truncated = true
	}

	// Index credentials by JTI so each edge can locate its parent's
	// scopes in O(1) for the attenuation diff.
	byJTI := make(map[string]*domain.IssuedCredential, len(creds))
	for _, c := range creds {
		byJTI[c.JTI] = c
	}

	// Collect distinct identity IDs (excluding nils) for one batch
	// lookup. Some credentials may have IdentityID nil — those still
	// produce edges but contribute no node on their own.
	idSet := make(map[string]struct{}, len(creds))
	for _, c := range creds {
		if c.IdentityID != nil && *c.IdentityID != "" {
			idSet[*c.IdentityID] = struct{}{}
		}
	}
	ids := make([]string, 0, len(idSet))
	for id := range idSet {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	identities, err := s.identityRepo.GetByIDs(ctx, ids, accountID, projectID)
	if err != nil {
		log.Warn().Err(err).Msg("identity batch load failed; graph nodes will be empty")
	}

	nodes := make([]*GraphNode, 0, len(identities))
	for _, id := range identities {
		nodes = append(nodes, identityToNode(id))
	}

	edges := make([]*GraphEdge, 0, len(creds))
	for _, c := range creds {
		edge := credentialToEdge(c)
		if c.ParentJTI != "" {
			if parent, ok := byJTI[c.ParentJTI]; ok {
				edge.From = identityIDOrEmpty(parent.IdentityID)
				edge.ScopesIn = parent.Scopes
				edge.Attenuated = setDiff(parent.Scopes, c.Scopes)
			}
		}
		edges = append(edges, edge)
	}

	return &Graph{
		Nodes:     nodes,
		Edges:     edges,
		FocalID:   focalID,
		Truncated: truncated,
	}
}

// mergeByJTI merges two credential slices into one, de-duping by JTI.
// Order is preserved from the first slice; new entries from the second
// slice are appended in their original order.
func mergeByJTI(a, b []*domain.IssuedCredential) []*domain.IssuedCredential {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]*domain.IssuedCredential, 0, len(a)+len(b))
	for _, c := range a {
		if _, ok := seen[c.JTI]; ok {
			continue
		}
		seen[c.JTI] = struct{}{}
		out = append(out, c)
	}
	for _, c := range b {
		if _, ok := seen[c.JTI]; ok {
			continue
		}
		seen[c.JTI] = struct{}{}
		out = append(out, c)
	}
	return out
}

// identityToNode reduces an Identity to the GraphNode subset.
func identityToNode(id *domain.Identity) *GraphNode {
	return &GraphNode{
		ID:           id.ID,
		WIMSEURI:     id.WIMSEURI,
		Name:         id.Name,
		IdentityType: string(id.IdentityType),
		TrustLevel:   string(id.TrustLevel),
		Status:       string(id.Status),
	}
}

// credentialToEdge converts an IssuedCredential into the wire-shape
// GraphEdge, prepopulating fields that do not depend on a parent
// lookup. The caller fills in From / ScopesIn / Attenuated for
// non-root edges.
func credentialToEdge(c *domain.IssuedCredential) *GraphEdge {
	scopesOut := c.Scopes
	if scopesOut == nil {
		scopesOut = []string{}
	}
	return &GraphEdge{
		To:              identityIDOrEmpty(c.IdentityID),
		JTI:             c.JTI,
		ParentJTI:       c.ParentJTI,
		MissionID:       c.MissionID,
		IssuedAt:        c.IssuedAt,
		ExpiresAt:       c.ExpiresAt,
		GrantType:       string(c.GrantType),
		DelegationDepth: c.DelegationDepth,
		// ScopesIn defaults to ScopesOut for root credentials so the
		// triple is always populated; the parent-lookup branch
		// overwrites this for non-root edges.
		ScopesIn:     scopesOut,
		ScopesOut:    scopesOut,
		Attenuated:   []string{},
		IsRevoked:    c.IsRevoked,
		RevokedAt:    c.RevokedAt,
		RevokeReason: c.RevokeReason,
	}
}

func identityIDOrEmpty(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// setDiff returns the elements in a that are not in b, preserving the
// order from a. Used to compute the attenuated-scopes set on each edge.
func setDiff(a, b []string) []string {
	if len(a) == 0 {
		return []string{}
	}
	inB := make(map[string]struct{}, len(b))
	for _, s := range b {
		inB[s] = struct{}{}
	}
	out := make([]string, 0)
	for _, s := range a {
		if _, ok := inB[s]; !ok {
			out = append(out, s)
		}
	}
	return out
}
