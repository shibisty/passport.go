package refresh

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"passport"
)

type fakeIssuer struct{ n int }

func (f *fakeIssuer) Issue(_ context.Context, id *passport.Identity, ttl time.Duration) (string, error) {
	f.n++
	if id.ProviderUserID == "fail" {
		return "", errors.New("issue failed")
	}
	return "access-" + id.ProviderUserID + "-" + string(rune('0'+f.n)), nil
}

var ctx = context.Background()
var ann = &passport.Identity{Provider: "local", ProviderUserID: "7", Raw: map[string]any{"secret": 1}}

func TestRotation(t *testing.T) {
	store := NewMemoryStore()
	r := New(store, time.Hour)
	iss := &fakeIssuer{}
	p1, err := r.Issue(ctx, iss, ann, 15*time.Minute)
	if err != nil || p1.Access == "" || len(p1.Refresh) < 40 || p1.ExpiresIn != 900 || p1.TokenType != "Bearer" {
		t.Fatalf("Issue: %+v %v", p1, err)
	}
	rec, _ := store.Get(ctx, hash(p1.Refresh))
	if rec.Identity.Raw != nil || strings.Contains(rec.ID, p1.Refresh) {
		t.Fatalf("stored: %+v", rec)
	}
	p2, err := r.Rotate(ctx, iss, p1.Refresh, 15*time.Minute)
	if err != nil || p2.Refresh == p1.Refresh || p2.Access == p1.Access {
		t.Fatalf("Rotate: %+v %v", p2, err)
	}
	// The spent p1 is presented again: the family (p2 too) is revoked.
	if _, err := r.Rotate(ctx, iss, p1.Refresh, time.Minute); !errors.Is(err, ErrReused) {
		t.Fatalf("reuse: %v", err)
	}
	if _, err := r.Rotate(ctx, iss, p2.Refresh, time.Minute); !errors.Is(err, ErrInvalid) {
		t.Fatalf("family not revoked: %v", err)
	}
	if _, err := r.Rotate(ctx, iss, "nope", time.Minute); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown: %v", err)
	}
}

func TestExpiryAndRevoke(t *testing.T) {
	now := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	r := New(NewMemoryStore(), time.Hour).WithClock(func() time.Time { return now })
	iss := &fakeIssuer{}
	p, _ := r.Issue(ctx, iss, ann, time.Minute)
	other, _ := r.Issue(ctx, iss, ann, time.Minute) // another login
	now = now.Add(time.Hour)
	if _, err := r.Rotate(ctx, iss, p.Refresh, time.Minute); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expired: %v", err)
	}
	now = now.Add(-30 * time.Minute)
	if err := r.Revoke(ctx, other.Refresh); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Rotate(ctx, iss, other.Refresh, time.Minute); !errors.Is(err, ErrInvalid) {
		t.Fatalf("revoked: %v", err)
	}
	if err := r.Revoke(ctx, "unknown"); err != nil {
		t.Fatalf("revoking an unknown token: %v", err)
	}
	if _, err := r.Issue(ctx, iss, &passport.Identity{ProviderUserID: "fail"}, time.Minute); err == nil {
		t.Fatal("issuer error lost")
	}
}

// Two requests rotate the same token at once: exactly one wins.
func TestConcurrentRotate(t *testing.T) {
	r := New(NewMemoryStore(), time.Hour)
	iss := &fakeIssuer{}
	p, _ := r.Issue(ctx, iss, ann, time.Minute)
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.Rotate(ctx, &fakeIssuer{}, p.Refresh, time.Minute); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d winners", wins)
	}
}

// failing store paths
type failStore struct {
	*MemoryStore
	get, spend, revoke, save error
	spendLoses               bool
}

func (f *failStore) Get(ctx context.Context, id string) (*Record, error) {
	if f.get != nil {
		return nil, f.get
	}
	return f.MemoryStore.Get(ctx, id)
}
func (f *failStore) Spend(ctx context.Context, id string) (bool, error) {
	if f.spend != nil {
		return false, f.spend
	}
	if f.spendLoses {
		return false, nil
	}
	return f.MemoryStore.Spend(ctx, id)
}
func (f *failStore) RevokeFamily(ctx context.Context, fam string) error {
	if f.revoke != nil {
		return f.revoke
	}
	return f.MemoryStore.RevokeFamily(ctx, fam)
}
func (f *failStore) Save(ctx context.Context, rec Record) error {
	if f.save != nil {
		return f.save
	}
	return f.MemoryStore.Save(ctx, rec)
}

func TestStoreErrors(t *testing.T) {
	boom := errors.New("boom")
	fs := &failStore{MemoryStore: NewMemoryStore()}
	r := New(fs, time.Hour)
	iss := &fakeIssuer{}
	p, _ := r.Issue(ctx, iss, ann, time.Minute)

	fs.get = boom
	if _, err := r.Rotate(ctx, iss, p.Refresh, time.Minute); !errors.Is(err, boom) {
		t.Fatalf("get: %v", err)
	}
	if err := r.Revoke(ctx, p.Refresh); !errors.Is(err, boom) {
		t.Fatalf("revoke get: %v", err)
	}
	fs.get = nil
	fs.spend = boom
	if _, err := r.Rotate(ctx, iss, p.Refresh, time.Minute); !errors.Is(err, boom) {
		t.Fatalf("spend: %v", err)
	}
	fs.spend, fs.spendLoses, fs.revoke = nil, true, boom
	if _, err := r.Rotate(ctx, iss, p.Refresh, time.Minute); !errors.Is(err, ErrReused) || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("lost race with a failing revoke: %v", err)
	}
	fs.spendLoses, fs.revoke, fs.save = false, nil, boom
	if _, err := r.Issue(ctx, iss, ann, time.Minute); !errors.Is(err, boom) {
		t.Fatalf("save: %v", err)
	}
	if NewMemoryStore().Len() != 0 {
		t.Fatal("Len")
	}
}
