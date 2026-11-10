package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/highflame-ai/zeroid/domain"
)

// fakeIdentityStore models IdentityRepository.GetByIDInAccounts: it returns a
// row only when its account is in the requested set, and sql.ErrNoRows
// otherwise. `ignoreAccountFilter` simulates a lookup that forgot its WHERE
// clause, to prove the admission check does not rest on the query alone.
type fakeIdentityStore struct {
	rows                map[string]*domain.Identity
	ignoreAccountFilter bool
	err                 error
	calls               int
	gotAccounts         []string
}

func (f *fakeIdentityStore) lookup(_ context.Context, id string, accounts []string) (*domain.Identity, error) {
	f.calls++
	f.gotAccounts = accounts
	if f.err != nil {
		return nil, f.err
	}
	row, ok := f.rows[id]
	if !ok || (!f.ignoreAccountFilter && !slices.Contains(accounts, row.AccountID)) {
		return nil, fmt.Errorf("failed to get identity: %w", sql.ErrNoRows)
	}
	cp := *row
	return &cp, nil
}

func linkedClient(identityID string) *domain.OAuthClient {
	return &domain.OAuthClient{ClientID: "idjag-client", IdentityID: &identityID}
}

const (
	tIssuer   = "https://idp.example.test"
	tLinkedID = "11111111-1111-4111-8111-111111111111"
	tAcctA    = "acct-a"
	tAcctB    = "acct-b"
	tProj     = "proj-a"
)

const tCIMD = "https://client.example.test/client.json"

func cimdClient(clientID string) *domain.OAuthClient {
	return &domain.OAuthClient{ClientID: clientID, RegistrationSource: domain.RegistrationSourceCIMD,
		TokenEndpointAuthMethod: clientAuthMethodPrivateKeyJWT, IsActive: true}
}

func activeIdentity(acct, proj string) *domain.Identity {
	return &domain.Identity{ID: tLinkedID, AccountID: acct, ProjectID: proj, Status: domain.IdentityStatusActive}
}

func TestDeriveIDJAGTenant(t *testing.T) {
	past := time.Now().Add(-time.Hour)

	cases := []struct {
		name       string
		allowed    []string
		client     *domain.OAuthClient
		store      *fakeIdentityStore
		reqAccount string
		reqProject string

		wantTenant  idJAGTenant
		wantCode    string
		wantStatus  int
		wantNoQuery bool
	}{
		// ── #630's table, under ADR 0042 D5 ────────────────────────────────
		{
			name:       "client tenant in allowed_accounts, no request fields → derived",
			allowed:    []string{tAcctA},
			client:     linkedClient(tLinkedID),
			store:      &fakeIdentityStore{rows: map[string]*domain.Identity{tLinkedID: activeIdentity(tAcctA, tProj)}},
			wantTenant: idJAGTenant{AccountID: tAcctA, ProjectID: tProj},
		},
		{
			name:       "client tenant is one of several allowed_accounts → that one, unambiguously",
			allowed:    []string{tAcctB, tAcctA},
			client:     linkedClient(tLinkedID),
			store:      &fakeIdentityStore{rows: map[string]*domain.Identity{tLinkedID: activeIdentity(tAcctA, tProj)}},
			wantTenant: idJAGTenant{AccountID: tAcctA, ProjectID: tProj},
		},
		{
			name:     "client tenant NOT in allowed_accounts → invalid_grant",
			allowed:  []string{tAcctB},
			client:   linkedClient(tLinkedID),
			store:    &fakeIdentityStore{rows: map[string]*domain.Identity{tLinkedID: activeIdentity(tAcctA, tProj)}},
			wantCode: "invalid_grant", wantStatus: http.StatusBadRequest,
		},
		{
			name:     "client tenant NOT in allowed_accounts, even if the lookup ignores its filter → invalid_grant",
			allowed:  []string{tAcctB},
			client:   linkedClient(tLinkedID),
			store:    &fakeIdentityStore{ignoreAccountFilter: true, rows: map[string]*domain.Identity{tLinkedID: activeIdentity(tAcctA, tProj)}},
			wantCode: "invalid_grant", wantStatus: http.StatusBadRequest,
		},
		{
			name:       "no client tenant, several allowed_accounts → refused, the request may not pick",
			allowed:    []string{tAcctA, tAcctB},
			client:     &domain.OAuthClient{ClientID: "unlinked"},
			store:      &fakeIdentityStore{},
			reqAccount: tAcctA, reqProject: tProj,
			wantCode: "invalid_grant", wantStatus: http.StatusBadRequest, wantNoQuery: true,
		},
		{
			name:     "no client tenant, single allowed account → refused: no project can be derived",
			allowed:  []string{tAcctA},
			client:   &domain.OAuthClient{ClientID: "unlinked"},
			store:    &fakeIdentityStore{},
			wantCode: "invalid_grant", wantStatus: http.StatusBadRequest, wantNoQuery: true,
		},
		{
			name:       "no client tenant, single allowed account, request names a project → still refused",
			allowed:    []string{tAcctA},
			client:     &domain.OAuthClient{ClientID: "unlinked"},
			store:      &fakeIdentityStore{},
			reqAccount: tAcctA, reqProject: tProj,
			wantCode: "invalid_grant", wantStatus: http.StatusBadRequest, wantNoQuery: true,
		},
		{
			name:     "empty identity_id string counts as no link",
			allowed:  []string{tAcctA},
			client:   func() *domain.OAuthClient { e := ""; return &domain.OAuthClient{IdentityID: &e} }(),
			store:    &fakeIdentityStore{},
			wantCode: "invalid_grant", wantStatus: http.StatusBadRequest, wantNoQuery: true,
		},
		{
			name:     "empty allowed_accounts admits nothing (never 'any')",
			allowed:  nil,
			client:   linkedClient(tLinkedID),
			store:    &fakeIdentityStore{ignoreAccountFilter: true, rows: map[string]*domain.Identity{tLinkedID: activeIdentity(tAcctA, tProj)}},
			wantCode: "invalid_grant", wantStatus: http.StatusBadRequest, wantNoQuery: true,
		},

		// ── Request fields: checked, never consulted ─────────────────────────
		{
			name:       "request names the derived tenant → accepted",
			allowed:    []string{tAcctA},
			client:     linkedClient(tLinkedID),
			store:      &fakeIdentityStore{rows: map[string]*domain.Identity{tLinkedID: activeIdentity(tAcctA, tProj)}},
			reqAccount: tAcctA, reqProject: tProj,
			wantTenant: idJAGTenant{AccountID: tAcctA, ProjectID: tProj},
		},
		{
			name:       "request names another ALLOWED account → invalid_grant, not a choice",
			allowed:    []string{tAcctA, tAcctB},
			client:     linkedClient(tLinkedID),
			store:      &fakeIdentityStore{rows: map[string]*domain.Identity{tLinkedID: activeIdentity(tAcctA, tProj)}},
			reqAccount: tAcctB,
			wantCode:   "invalid_grant", wantStatus: http.StatusBadRequest,
		},
		{
			name:       "request names another project → invalid_grant",
			allowed:    []string{tAcctA},
			client:     linkedClient(tLinkedID),
			store:      &fakeIdentityStore{rows: map[string]*domain.Identity{tLinkedID: activeIdentity(tAcctA, tProj)}},
			reqAccount: tAcctA, reqProject: "proj-other",
			wantCode: "invalid_grant", wantStatus: http.StatusBadRequest,
		},
		{
			name:       "request names only a wrong project → invalid_grant",
			allowed:    []string{tAcctA},
			client:     linkedClient(tLinkedID),
			store:      &fakeIdentityStore{rows: map[string]*domain.Identity{tLinkedID: activeIdentity(tAcctA, tProj)}},
			reqProject: "proj-other",
			wantCode:   "invalid_grant", wantStatus: http.StatusBadRequest,
		},

		// ── The linked identity itself ───────────────────────────────────────
		{
			name:    "linked identity suspended → invalid_grant (ADR 0042 D7)",
			allowed: []string{tAcctA},
			client:  linkedClient(tLinkedID),
			store: &fakeIdentityStore{rows: map[string]*domain.Identity{tLinkedID: func() *domain.Identity {
				i := activeIdentity(tAcctA, tProj)
				i.Status = domain.IdentityStatusSuspended
				return i
			}()}},
			wantCode: "invalid_grant", wantStatus: http.StatusBadRequest,
		},
		{
			name:    "linked identity expired → invalid_grant",
			allowed: []string{tAcctA},
			client:  linkedClient(tLinkedID),
			store: &fakeIdentityStore{rows: map[string]*domain.Identity{tLinkedID: func() *domain.Identity {
				i := activeIdentity(tAcctA, tProj)
				i.ExpiresAt = &past
				return i
			}()}},
			wantCode: "invalid_grant", wantStatus: http.StatusBadRequest,
		},
		{
			name:     "dangling link → invalid_grant",
			allowed:  []string{tAcctA},
			client:   linkedClient(tLinkedID),
			store:    &fakeIdentityStore{rows: map[string]*domain.Identity{}},
			wantCode: "invalid_grant", wantStatus: http.StatusBadRequest,
		},
		{
			name:     "store failure is a server error, not a tenant decision",
			allowed:  []string{tAcctA},
			client:   linkedClient(tLinkedID),
			store:    &fakeIdentityStore{err: errors.New("connection reset")},
			wantCode: "server_error", wantStatus: http.StatusInternalServerError,
		},

		// ── CIMD clients (firehog#701): no D6 binding exists yet ─────────────
		//
		// Every one of these is refused. None of the inputs a CIMD client
		// arrives with may choose a tenant: not the request, not a single
		// allowed account, not the document.
		{
			name:     "CIMD client, single allowed account, no request fields → invalid_grant",
			allowed:  []string{tAcctA},
			client:   cimdClient(tCIMD),
			store:    &fakeIdentityStore{rows: map[string]*domain.Identity{tLinkedID: activeIdentity(tAcctA, tProj)}},
			wantCode: "invalid_grant", wantStatus: http.StatusBadRequest, wantNoQuery: true,
		},
		{
			name:       "CIMD client naming an allowed tenant on the request → invalid_grant",
			allowed:    []string{tAcctA},
			client:     cimdClient(tCIMD),
			store:      &fakeIdentityStore{},
			reqAccount: tAcctA, reqProject: tProj,
			wantCode: "invalid_grant", wantStatus: http.StatusBadRequest, wantNoQuery: true,
		},
		{
			name:       "CIMD client naming a tenant the issuer does not allow → invalid_grant",
			allowed:    []string{tAcctA},
			client:     cimdClient(tCIMD),
			store:      &fakeIdentityStore{},
			reqAccount: tAcctB, reqProject: tProj,
			wantCode: "invalid_grant", wantStatus: http.StatusBadRequest, wantNoQuery: true,
		},
		{
			name: "CIMD client carrying an identity_id is still not trusted for one",
			// A synthesized client never has one; if one ever appeared it must
			// not become a tenant source for a self-asserted client.
			allowed: []string{tAcctA},
			client: func() *domain.OAuthClient {
				c := cimdClient(tCIMD)
				id := tLinkedID
				c.IdentityID = &id
				return c
			}(),
			store:    &fakeIdentityStore{rows: map[string]*domain.Identity{tLinkedID: activeIdentity(tAcctA, tProj)}},
			wantCode: "invalid_grant", wantStatus: http.StatusBadRequest, wantNoQuery: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &domain.ExternalIssuerConfig{Issuer: tIssuer, AllowedAccounts: tc.allowed}
			got, err := deriveIDJAGTenant(context.Background(), cfg, tc.client,
				tc.store.lookup, tc.reqAccount, tc.reqProject)

			if tc.wantNoQuery && tc.store.calls != 0 {
				t.Errorf("expected no identity lookup, got %d", tc.store.calls)
			}
			if tc.wantCode != "" {
				requireOAuthError(t, err, tc.wantCode, tc.wantStatus)
				if got != (idJAGTenant{}) {
					t.Errorf("a refusal must return no tenant, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.wantTenant {
				t.Fatalf("tenant = %+v, want %+v", got, tc.wantTenant)
			}
			// The lookup is restricted to exactly the issuer's admitted set.
			if !slices.Equal(tc.store.gotAccounts, tc.allowed) {
				t.Errorf("lookup scoped to %v, want the issuer's allowed_accounts %v", tc.store.gotAccounts, tc.allowed)
			}
		})
	}
}

// TestDeriveIDJAGTenant_ErrorsDoNotEchoTheDerivedTenant pins that a mismatch
// refusal does not tell the caller which tenant it should have sent.
func TestDeriveIDJAGTenant_ErrorsDoNotEchoTheDerivedTenant(t *testing.T) {
	store := &fakeIdentityStore{rows: map[string]*domain.Identity{tLinkedID: activeIdentity(tAcctA, tProj)}}
	cfg := &domain.ExternalIssuerConfig{Issuer: tIssuer, AllowedAccounts: []string{tAcctA, tAcctB}}
	_, err := deriveIDJAGTenant(context.Background(), cfg,
		linkedClient(tLinkedID), store.lookup, tAcctB, "proj-x")
	var oe *OAuthError
	if !errors.As(err, &oe) {
		t.Fatalf("expected OAuthError, got %v", err)
	}
	for _, leak := range []string{tAcctA, tProj} {
		if strings.Contains(oe.Description, leak) {
			t.Errorf("error_description %q echoes the derived tenant value %q", oe.Description, leak)
		}
	}
}
