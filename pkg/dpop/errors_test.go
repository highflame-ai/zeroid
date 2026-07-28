package dpop

import (
	"errors"
	"testing"
)

func TestError_IsMatchesByCode(t *testing.T) {
	e := withCause(ErrReplay, errors.New("underlying"))
	if !errors.Is(e, ErrReplay) {
		t.Fatal("withCause(ErrReplay, _) should errors.Is(ErrReplay)")
	}
	if errors.Is(e, ErrInvalidProof) {
		t.Fatal("withCause(ErrReplay, _) should NOT errors.Is(ErrInvalidProof)")
	}
}

func TestError_Unwrap(t *testing.T) {
	cause := errors.New("postgres down")
	e := withCause(ErrStorageFailure, cause)
	if !errors.Is(e, cause) {
		t.Fatal("Unwrap chain broken")
	}
}

func TestError_String(t *testing.T) {
	e := wrap(CodeReplay, "jti seen twice", errors.New("constraint violation"))
	s := e.Error()
	if s == "" {
		t.Fatal("Error string should not be empty")
	}
	// Must surface code, message, and cause for debugging.
	mustContain(t, s, "dpop:")
	mustContain(t, s, CodeReplay)
	mustContain(t, s, "jti seen twice")
	mustContain(t, s, "constraint violation")
}

func TestError_StringNoCause(t *testing.T) {
	e := wrap(CodeReplay, "jti seen twice", nil)
	s := e.Error()
	mustContain(t, s, CodeReplay)
	mustContain(t, s, "jti seen twice")
}

func TestIsClientFault(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"replay", ErrReplay, true},
		{"invalid signature", ErrInvalidSignature, true},
		{"htu mismatch", ErrHTUMismatch, true},
		{"storage failure", ErrStorageFailure, false},
		{"raw error", errors.New("not a dpop error"), false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsClientFault(tc.err); got != tc.want {
				t.Fatalf("IsClientFault(%v) = %v; want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestError_AsExtractsCode(t *testing.T) {
	e := wrap(CodeBodyHashMismatch, "diff", nil)
	var de *Error
	if !errors.As(e, &de) {
		t.Fatal("errors.As failed")
	}
	if de.Code != CodeBodyHashMismatch {
		t.Fatalf("Code = %q, want %q", de.Code, CodeBodyHashMismatch)
	}
}

func mustContain(t *testing.T, s, substr string) {
	t.Helper()
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return
		}
	}
	t.Fatalf("expected %q in %q", substr, s)
}
