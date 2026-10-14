package zeroid

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// A denial must end the chain even when the resolver's error also matches
// ErrPrincipalNotApplicable (errors.Join, or a %w of both). Continuing would let
// a later resolver authenticate the same request and issue a code the resource
// owner has just declined.
func TestResolvePrincipal_DenialStopsChainEvenWhenAlsoNotApplicable(t *testing.T) {
	for name, deny := range map[string]error{
		"joined":  errors.Join(ErrPrincipalNotApplicable, ErrPrincipalAccessDenied),
		"wrapped": fmt.Errorf("consent: %w (%w)", ErrPrincipalNotApplicable, ErrPrincipalAccessDenied),
	} {
		t.Run(name, func(t *testing.T) {
			s := &Server{}
			s.RegisterPrincipalResolver("consent", func(context.Context, *AuthorizeRequest) (*Principal, error) {
				return nil, deny
			})

			laterRan := false
			s.RegisterPrincipalResolver("cookie", func(context.Context, *AuthorizeRequest) (*Principal, error) {
				laterRan = true

				return &Principal{AccountID: "acct", ProjectID: "proj", UserID: "user"}, nil
			})

			p, matched, err := s.resolvePrincipal(context.Background(), &AuthorizeRequest{})
			if p != nil || laterRan {
				t.Fatalf("chain continued past a denial: principal=%v laterRan=%v", p, laterRan)
			}

			if !errors.Is(err, ErrPrincipalAccessDenied) {
				t.Fatalf("err = %v, want ErrPrincipalAccessDenied", err)
			}

			if matched != "consent" {
				t.Errorf("matched = %q, want the denying resolver", matched)
			}
		})
	}
}

// A plain ErrPrincipalNotApplicable still defers to the next resolver.
func TestResolvePrincipal_NotApplicableStillContinues(t *testing.T) {
	s := &Server{}
	s.RegisterPrincipalResolver("first", func(context.Context, *AuthorizeRequest) (*Principal, error) {
		return nil, fmt.Errorf("no header: %w", ErrPrincipalNotApplicable)
	})
	s.RegisterPrincipalResolver("second", func(context.Context, *AuthorizeRequest) (*Principal, error) {
		return &Principal{AccountID: "acct"}, nil
	})

	p, matched, err := s.resolvePrincipal(context.Background(), &AuthorizeRequest{})
	if err != nil || p == nil || matched != "second" {
		t.Fatalf("got (%v, %q, %v), want the second resolver's principal", p, matched, err)
	}
}
