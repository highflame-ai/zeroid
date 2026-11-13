package zeroid

import (
	"slices"
	"testing"
)

// The setter stores the validated list, and an invalid list leaves the
// current one in place rather than clearing or half-applying it.
func TestSetInteractiveLoginPassthroughParams(t *testing.T) {
	s := &Server{}

	if err := s.SetInteractiveLoginPassthroughParams("project_id", "project_id"); err != nil {
		t.Fatalf("valid list refused: %v", err)
	}

	if got := s.interactiveLoginPassthroughParams(); !slices.Equal(got, []string{"project_id"}) {
		t.Fatalf("stored %v, want [project_id]", got)
	}

	if err := s.SetInteractiveLoginPassthroughParams("tenant_hint", "redirect_uri"); err == nil {
		t.Fatal("a reserved protocol parameter was accepted")
	}

	if got := s.interactiveLoginPassthroughParams(); !slices.Equal(got, []string{"project_id"}) {
		t.Fatalf("a refused list changed the stored one to %v", got)
	}

	if err := s.SetInteractiveLoginPassthroughParams(); err != nil {
		t.Fatalf("clearing refused: %v", err)
	}

	if got := s.interactiveLoginPassthroughParams(); len(got) != 0 {
		t.Fatalf("clearing left %v", got)
	}
}
