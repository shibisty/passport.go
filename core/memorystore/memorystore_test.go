package memorystore

import (
	"context"
	"testing"
	"time"

	"passport"
	"passport/sessionstoretest"
)

func TestSuite(t *testing.T) {
	sessionstoretest.Run(t, New(), 100*time.Millisecond)
}

// Expired sessions that are no longer accessed are removed when new ones are created.
func TestSweepsExpired(t *testing.T) {
	s := New()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	ctx := context.Background()
	id := &passport.Identity{ProviderUserID: "1"}
	for i := 0; i < sweepEvery-1; i++ {
		if _, err := s.Create(ctx, id, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(2 * time.Minute)
	if _, err := s.Create(ctx, id, time.Hour); err != nil { // every sweepEvery-th session triggers a sweep
		t.Fatal(err)
	}
	if n := s.Len(); n != 1 {
		t.Fatalf("after sweep: %d sessions, want 1", n)
	}
}
