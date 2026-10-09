package redisstore

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"orm"
	"passport"
	"passport/sessionstoretest"
)

// fakeKV is an in-memory orm.KeyValueStore with a faithful TTL (in seconds, as in Redis).
type fakeKV struct {
	mu     sync.Mutex
	data   map[string]string
	exp    map[string]time.Time
	ttls   map[string]int
	getErr error
	setErr error
	delErr error
}

func newFakeKV() *fakeKV {
	return &fakeKV{data: map[string]string{}, exp: map[string]time.Time{}, ttls: map[string]int{}}
}

func (f *fakeKV) Driver() string             { return "fake" }
func (f *fakeKV) Ping(context.Context) error { return nil }
func (f *fakeKV) Close() error               { return nil }

func (f *fakeKV) Get(_ context.Context, k string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return "", f.getErr
	}
	v, ok := f.data[k]
	if !ok || (!f.exp[k].IsZero() && time.Now().After(f.exp[k])) {
		return "", orm.ErrNotFound
	}
	return v, nil
}

func (f *fakeKV) Set(_ context.Context, k string, v any, ttl int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.setErr != nil {
		return f.setErr
	}
	f.data[k] = v.(string)
	f.ttls[k] = ttl
	if ttl > 0 {
		f.exp[k] = time.Now().Add(time.Duration(ttl) * time.Second)
	}
	return nil
}

func (f *fakeKV) Del(_ context.Context, keys ...string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.delErr != nil {
		return 0, f.delErr
	}
	for _, k := range keys {
		delete(f.data, k)
	}
	return int64(len(keys)), nil
}

func (f *fakeKV) Exists(context.Context, ...string) (int64, error) { return 0, nil }

var ctx = context.Background()

func TestSuite(t *testing.T) {
	sessionstoretest.Run(t, New(newFakeKV()), time.Second)
}

// A TTL below one second does not turn into 0 ("forever").
func TestTTLRoundsUp(t *testing.T) {
	kv := newFakeKV()
	s := New(kv).WithPrefix("app:s:")
	for ttl, want := range map[time.Duration]int{
		500 * time.Millisecond:  1,
		time.Second:             1,
		1500 * time.Millisecond: 2,
		time.Hour:               3600,
	} {
		id, err := s.Create(ctx, &passport.Identity{ProviderUserID: "1"}, ttl)
		if err != nil {
			t.Fatal(err)
		}
		if got := kv.ttls["app:s:"+id]; got != want {
			t.Errorf("ttl %s → %d s, want %d", ttl, got, want)
		}
	}
	if _, err := s.Create(ctx, &passport.Identity{}, 0); err == nil {
		t.Error("TTL 0 must be rejected")
	}
}

// An unavailable store is an error, not "session not found".
func TestStorageErrors(t *testing.T) {
	kv := newFakeKV()
	s := New(kv)
	id, _ := s.Create(ctx, &passport.Identity{ProviderUserID: "1"}, time.Minute)

	kv.getErr = errors.New("connection refused")
	if _, err := s.Get(ctx, id); err == nil || errors.Is(err, passport.ErrSessionNotFound) || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("storage error must not look like a missing session: %v", err)
	}
	kv.getErr = nil

	kv.data[DefaultPrefix+id] = "{not json"
	if _, err := s.Get(ctx, id); err == nil || errors.Is(err, passport.ErrSessionNotFound) {
		t.Fatalf("corrupted session: %v", err)
	}
	if _, err := s.Get(ctx, ""); !errors.Is(err, passport.ErrSessionNotFound) {
		t.Fatalf("empty id: %v", err)
	}

	kv.setErr = errors.New("readonly")
	if _, err := s.Create(ctx, &passport.Identity{}, time.Minute); err == nil {
		t.Fatal("Set error must be returned")
	}
	kv.delErr = errors.New("down")
	if err := s.Destroy(ctx, id); err == nil {
		t.Fatal("Del error must be returned")
	}
}

func TestRawIsNotStored(t *testing.T) {
	kv := newFakeKV()
	id, _ := New(kv).Create(ctx, &passport.Identity{ProviderUserID: "1", Raw: map[string]any{"access_token": "secret"}}, time.Minute)
	if strings.Contains(kv.data[DefaultPrefix+id], "secret") {
		t.Fatal("provider profile (Raw) must not be stored in the session")
	}
}
