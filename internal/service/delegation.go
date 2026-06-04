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
type GraphEdge struct {
	From            string    `json:"from,omitempty"`
	To              string    `json:"to,omitempty"`
	JTI             string    `json:"jti"`
	ParentJTI       string    `json:"parent_jti,omitempty"`
	MissionID       string    `json:"mission_id,omitempty"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	GrantType       string    `json:"grant_type"`
	DelegationDepth int       `json:"delegation_depth"`
	ScopesIn        []string  `json:"scopes_in"`
	ScopesOut       []string  `json:"scopes_out"`
	Attenuated      []string  `json:"attenuated"`
	IsRevoked       bool      `json:"is_revoked"`
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

// GetGraph returns the depth-bounded local subgraph centered on
// identityID. The focal credential is identityID's most recent
// credential; the walk proceeds up `depth` hops via parent_jti and
// down `depth` hops via reverse parent_jti. Identities are enriched in
// one batch query.
//
// When the identity has issued no credentials yet, returns a one-node
// graph (just the identity, no edges). When the credential count
// exceeds MaxGraphNodes after the walk, Truncated is set on the
// response; credentials are capped at MaxGraphNodes.
func (s *DelegationService) GetGraph(ctx context.Context, identityID string, depth int, accountID, projectID string) (*Graph, error) {
	if depth < 1 {
		depth = 1
	}
	if depth > MaxGraphDepth {
		depth = MaxGraphDepth
	}

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

	// Walk every credential's delegation tree so the graph covers all
	// mission chains, not just the most recent one.
	//
	// FIX: Previously only creds[0] (most recent) was walked, so identities
	// with multiple credentials/missions only showed one tree in the graph.
	// This loop fixes that but issues N×(WalkUp+WalkDown) queries — for
	// identities with many credentials this may need rethinking (e.g. a
	// single multi-root CTE, or pagination/lazy-load per mission).
	var all []*domain.IssuedCredential
	for _, c := range creds {
		up, err := s.delegRepo.WalkUp(ctx, c.JTI, accountID, projectID, depth)
		if err != nil {
			return nil, err
		}
		down, err := s.delegRepo.WalkDown(ctx, c.JTI, accountID, projectID, depth)
		if err != nil {
			return nil, err
		}
		all = mergeByJTI(all, mergeByJTI(up, down))
	}

	graph := s.buildGraph(ctx, all, accountID, projectID, identityID)
	return graph, nil
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
		ScopesIn:   scopesOut,
		ScopesOut:  scopesOut,
		Attenuated: []string{},
		IsRevoked:  c.IsRevoked,
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
