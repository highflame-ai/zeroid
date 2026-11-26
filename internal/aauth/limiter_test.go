package aauth

import (
	"testing"
	"time"
)

func TestLimiterWindow(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	l := newLimiter(2, func() time.Time { return now })
	for i := 0; i < 2; i++ {
		if ok, _ := l.allow("a"); !ok {
			t.Fatalf("request %d refused inside the limit", i)
		}
	}
	ok, wait := l.allow("a")
	if ok || wait != time.Minute {
		t.Fatalf("third request: ok=%v wait=%v, want refused with a minute to wait", ok, wait)
	}
	if ok, _ := l.allow("b"); !ok {
		t.Fatal("another key shares the limit")
	}
	now = now.Add(time.Minute)
	if ok, _ := l.allow("a"); !ok {
		t.Fatal("the window did not reset")
	}
	if d := rateLimited(1500 * time.Millisecond).retryAfter; d != 2 {
		t.Fatalf("Retry-After rounds up: got %d", d)
	}
}
