package ratelimit

import (
	"testing"
	"time"
)

func TestWindow(t *testing.T) {
	now := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	l := New(3, time.Minute).WithClock(func() time.Time { return now })
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("ip"); !ok {
			t.Fatalf("attempt %d refused", i+1)
		}
		now = now.Add(10 * time.Second)
	}
	ok, retry := l.Allow("ip")
	if ok || retry != 30*time.Second {
		t.Fatalf("4th attempt: %v, retry %v", ok, retry)
	}
	if ok, _ := l.Allow("other"); !ok {
		t.Fatal("keys share a limit")
	}
	now = now.Add(31 * time.Second) // the first attempt left the window
	if ok, _ := l.Allow("ip"); !ok {
		t.Fatal("sliding window did not slide")
	}
	l.Reset("ip")
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("ip"); !ok {
			t.Fatal("Reset did not forget")
		}
	}
	if New(0, time.Second).max != 1 {
		t.Fatal("max < 1")
	}
}

func TestSweep(t *testing.T) {
	now := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	l := New(1, time.Second).WithClock(func() time.Time { return now })
	for i := 0; i < 1023; i++ {
		l.Allow(string(rune('a'+i%26)) + string(rune(i)))
	}
	now = now.Add(time.Hour)
	l.Allow("last")
	if len(l.hits) != 1 {
		t.Fatalf("%d keys kept after the sweep", len(l.hits))
	}
}
