// Package sessionstoretest is a shared test suite for implementations of
// passport.SessionStore (memorystore, passport-session-redis, third-party ones).
//
//	func TestStore(t *testing.T) {
//		sessionstoretest.Run(t, myStore, time.Second)
//	}
package sessionstoretest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"passport"
)

// Run tests creation, reading, deletion, expiry and concurrent access.
// shortTTL is the minimum lifetime the store honours exactly
// (one second for Redis); the test waits shortTTL + 300 ms.
func Run(t *testing.T, store passport.SessionStore, shortTTL time.Duration) {
	t.Helper()
	ctx := context.Background()
	identity := &passport.Identity{
		Provider: "local", ProviderUserID: "42", Email: "ann@example.com",
		EmailVerified: true, Name: "Ann", AvatarURL: "https://example.com/a.png",
		Raw: map[string]any{"secret": "must not be stored"},
	}

	t.Run("create get destroy", func(t *testing.T) {
		id, err := store.Create(ctx, identity, time.Hour)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if len(id) < 32 {
			t.Fatalf("session id %q is too short to be unguessable", id)
		}
		got, err := store.Get(ctx, id)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		want := *identity
		want.Raw = nil
		if got.Provider != want.Provider || got.ProviderUserID != want.ProviderUserID || got.Email != want.Email ||
			got.EmailVerified != want.EmailVerified || got.Name != want.Name || got.AvatarURL != want.AvatarURL {
			t.Fatalf("Get = %+v, want %+v", *got, want)
		}
		got.Name = "changed"
		if again, _ := store.Get(ctx, id); again == nil || again.Name != "Ann" {
			t.Fatal("Get must return a copy: changing it must not change the stored session")
		}
		if err := store.Destroy(ctx, id); err != nil {
			t.Fatalf("Destroy: %v", err)
		}
		if _, err := store.Get(ctx, id); !errors.Is(err, passport.ErrSessionNotFound) {
			t.Fatalf("Get after Destroy: want ErrSessionNotFound, got %v", err)
		}
		if err := store.Destroy(ctx, id); err != nil {
			t.Fatalf("Destroy of a missing session must not fail: %v", err)
		}
	})

	t.Run("unknown id", func(t *testing.T) {
		if _, err := store.Get(ctx, "no-such-session"); !errors.Is(err, passport.ErrSessionNotFound) {
			t.Fatalf("want ErrSessionNotFound, got %v", err)
		}
	})

	t.Run("ids are unique", func(t *testing.T) {
		seen := map[string]bool{}
		for i := 0; i < 50; i++ {
			id, err := store.Create(ctx, identity, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if seen[id] {
				t.Fatalf("duplicate session id %s", id)
			}
			seen[id] = true
		}
	})

	t.Run("expires", func(t *testing.T) {
		id, err := store.Create(ctx, identity, shortTTL)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Get(ctx, id); err != nil {
			t.Fatalf("fresh session: %v", err)
		}
		time.Sleep(shortTTL + 300*time.Millisecond)
		if _, err := store.Get(ctx, id); !errors.Is(err, passport.ErrSessionNotFound) {
			t.Fatalf("expired session: want ErrSessionNotFound, got %v", err)
		}
	})

	t.Run("concurrent use", func(t *testing.T) {
		var wg sync.WaitGroup
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 20; i++ {
					id, err := store.Create(ctx, identity, time.Minute)
					if err != nil {
						t.Error(err)
						return
					}
					if _, err := store.Get(ctx, id); err != nil {
						t.Error(err)
						return
					}
					_ = store.Destroy(ctx, id)
				}
			}()
		}
		wg.Wait()
	})
}
