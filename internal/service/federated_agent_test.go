package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/highflame-ai/zeroid/domain"
)

type fakeBindings map[string]*domain.IssuerBinding

func (f fakeBindings) EnabledBinding(_ context.Context, issuerID, subjectKey string) (*domain.IssuerBinding, error) {
	if b, ok := f[issuerID+"|"+subjectKey]; ok && b.Enabled {
		return b, nil
	}
	return nil, nil
}

func identityLookupOf(ids ...*domain.Identity) linkedIdentityLookup {
	return func(_ context.Context, id string, accounts []string) (*domain.Identity, error) {
		for _, i := range ids {
			if i.ID == id && slices.Contains(accounts, i.AccountID) {
				c := *i
				return &c, nil
			}
		}
		return nil, fmt.Errorf("lookup: %w", sql.ErrNoRows)
	}
}

func oauthCode(err error) string {
	var oe *OAuthError
	if errors.As(err, &oe) {
		return oe.Code
	}
	return ""
}

func TestBindAgent(t *testing.T) {
	row := &domain.ExternalIssuer{ID: "row-1", AccountID: "acct-a", Issuer: "https://idp"}
	active := &domain.Identity{ID: "agent-1", AccountID: "acct-a", ProjectID: "proj-1", Status: domain.IdentityStatusActive}
	discovered := &domain.Identity{ID: "agent-2", AccountID: "acct-a", ProjectID: "proj-1", Status: domain.IdentityStatusDiscovered}
	pending := &domain.Identity{ID: "agent-3", AccountID: "acct-a", ProjectID: "proj-1", Status: domain.IdentityStatusPending}
	foreign := &domain.Identity{ID: "agent-4", AccountID: "acct-b", ProjectID: "proj-9", Status: domain.IdentityStatusActive}
	bindings := fakeBindings{
		"row-1|okta-client-1": {IdentityID: "agent-1", Enabled: true},
		"row-1|okta-client-2": {IdentityID: "agent-2", Enabled: true},
		"row-1|okta-client-3": {IdentityID: "agent-3", Enabled: true},
		"row-1|okta-client-4": {IdentityID: "agent-4", Enabled: true},
		"row-1|disabled":      {IdentityID: "agent-1", Enabled: false},
	}
	lookup := identityLookupOf(active, discovered, pending, foreign)
	ctx := context.Background()
	linked := func(id string) *domain.OAuthClient { return &domain.OAuthClient{ClientID: "c", IdentityID: &id} }

	got, err := bindAgent(ctx, bindings, lookup, row, "okta-client-1", linked("agent-1"), federatedGrantIDJAG)
	if err != nil || got.ID != "agent-1" {
		t.Fatalf("bound agent: %v %v", got, err)
	}
	if got, err := bindAgent(ctx, bindings, lookup, row, "okta-client-1", nil, federatedGrantIDJAG); err != nil || got.ID != "agent-1" {
		t.Fatalf("no client to check (CIMD path passes nil-safe): %v %v", got, err)
	}

	for name, tc := range map[string]struct {
		key    string
		client *domain.OAuthClient
		msg    string
	}{
		"no act.sub":               {key: "", msg: "names no agent"},
		"no binding":               {key: "okta-client-9", msg: "no enabled binding"},
		"disabled binding":         {key: "disabled", msg: "no enabled binding"},
		"discovered agent (D7)":    {key: "okta-client-2", msg: "is discovered"},
		"pending agent (D7)":       {key: "okta-client-3", msg: "is pending"},
		"identity in another acct": {key: "okta-client-4", msg: "no identity in the issuer's account"},
		"client bound elsewhere":   {key: "okta-client-1", client: linked("agent-9"), msg: "not registered to the agent"},
		"client linked to nothing": {key: "okta-client-1", client: &domain.OAuthClient{ClientID: "c"}, msg: "not registered to the agent"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := bindAgent(ctx, bindings, lookup, row, tc.key, tc.client, federatedGrantIDJAG)
			if oauthCode(err) != "invalid_grant" || !strings.Contains(err.Error(), tc.msg) {
				t.Fatalf("err = %v, want invalid_grant containing %q", err, tc.msg)
			}
		})
	}
}

func TestFederatedTenant(t *testing.T) {
	id := &domain.Identity{AccountID: "a", ProjectID: "p"}
	if err := federatedTenant(id, "", ""); err != nil {
		t.Fatal("no request tenant is fine")
	}
	if err := federatedTenant(id, "a", "p"); err != nil {
		t.Fatal("the derived tenant is fine")
	}
	if oauthCode(federatedTenant(id, "b", "")) != "invalid_grant" || oauthCode(federatedTenant(id, "a", "q")) != "invalid_grant" {
		t.Fatal("a mismatched tenant is invalid_grant")
	}
}

func TestActorSubject(t *testing.T) {
	if actorSubject(map[string]any{"act": map[string]any{"sub": "0oa1", "sub_profile": "ai_agent"}}) != "0oa1" {
		t.Fatal("act.sub")
	}
	if actorSubject(map[string]any{"act": "0oa1"}) != "" || actorSubject(nil) != "" {
		t.Fatal("a malformed or absent act names no agent")
	}
}

func TestIsCurrentActor(t *testing.T) {
	sign := func(claims map[string]any) jwt.Token {
		tok := jwt.New()
		for k, v := range claims {
			_ = tok.Set(k, v)
		}
		return tok
	}
	agentA := &domain.Identity{ID: "a", WIMSEURI: "spiffe://d/acct/proj/agent/a"}

	rfcPerson := sign(map[string]any{"sub": "user_1", "principal_type": "user", "act": map[string]any{"sub": agentA.WIMSEURI}})
	actors := priorActorsOf(rfcPerson)
	if !isCurrentActor(actors, agentA) {
		t.Fatal("rfc8693: act.sub is the actor")
	}
	if isCurrentActor(actors, &domain.Identity{ID: "b", WIMSEURI: "spiffe://d/acct/proj/agent/b"}) {
		t.Fatal("rfc8693: another agent is a new actor")
	}
	rfcCode := sign(map[string]any{"sub": "user_1", "principal_type": "user", "client_id": "c"})
	if isCurrentActor(priorActorsOf(rfcCode), agentA) {
		t.Fatal("rfc8693: a root with no act has no current actor")
	}
	legacy := sign(map[string]any{"sub": "user_1", "act": map[string]any{"sub": agentA.WIMSEURI}})
	if isCurrentActor(priorActorsOf(legacy), agentA) {
		t.Fatal("legacy never collapses (ADR 0043 D1)")
	}

	if got := delegatorBefore(rfcPerson, actors); got != "user_1" {
		t.Fatalf("delegatorBefore = %q", got)
	}
	chain := sign(map[string]any{"sub": "user_1", "principal_type": "user", "act": map[string]any{"sub": "B", "act": map[string]any{"sub": "A"}}})
	if got := delegatorBefore(chain, priorActorsOf(chain)); got != "A" {
		t.Fatalf("delegatorBefore = %q", got)
	}
}
