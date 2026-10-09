package filestore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"passport"
	"passport/sessionstoretest"
)

var ctx = context.Background()

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "sessions"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSuite(t *testing.T) {
	sessionstoretest.Run(t, newStore(t), 200*time.Millisecond)
}

func TestFiles(t *testing.T) {
	s := newStore(t)
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(s.Dir()); st.Mode().Perm() != 0o700 {
			t.Errorf("directory mode %v, want 0700", st.Mode().Perm())
		}
	}
	id, err := s.Create(ctx, &passport.Identity{ProviderUserID: "1", Raw: map[string]any{"access_token": "secret"}}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(s.Dir(), id+".session"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret") {
		t.Fatal("provider profile (Raw) must not be stored in the session")
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(filepath.Join(s.Dir(), id+".session")); st.Mode().Perm() != 0o600 {
			t.Errorf("session file mode %v, want 0600", st.Mode().Perm())
		}
	}
	entries, _ := os.ReadDir(s.Dir())
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
	// The same directory, another process: sessions survive a restart.
	s2, err := New(s.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s2.Get(ctx, id); err != nil || got.ProviderUserID != "1" {
		t.Fatalf("reopened store: %v %v", got, err)
	}
}

// A session id comes from a cookie: it must never name another file.
func TestIDsCannotEscape(t *testing.T) {
	s := newStore(t)
	outside := filepath.Join(filepath.Dir(s.Dir()), "victim.session")
	os.WriteFile(outside, []byte(`{"identity":{"provider_user_id":"admin"},"expires":"2999-01-01T00:00:00Z"}`), 0o600)
	for _, id := range []string{"../victim", "..\\victim", "/etc/passwd", "", "ABCDEF" + strings.Repeat("0", 58), strings.Repeat("z", 64), strings.Repeat("0", 63)} {
		if _, err := s.Get(ctx, id); !errors.Is(err, passport.ErrSessionNotFound) {
			t.Errorf("Get(%q) = %v, want ErrSessionNotFound", id, err)
		}
		if err := s.Destroy(ctx, id); err != nil {
			t.Errorf("Destroy(%q) = %v", id, err)
		}
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatal("Destroy removed a file outside the store")
	}
}

func TestErrors(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Error("empty directory")
	}
	file := filepath.Join(t.TempDir(), "file")
	os.WriteFile(file, nil, 0o600)
	if _, err := New(file); err == nil {
		t.Error("a file is not a directory")
	}
	if _, err := New(filepath.Join(file, "sub")); err == nil {
		t.Error("cannot create a directory under a file")
	}
	s := newStore(t)
	if _, err := s.Create(ctx, &passport.Identity{}, 0); err == nil {
		t.Error("TTL 0 must be rejected")
	}
	id, _ := s.Create(ctx, &passport.Identity{ProviderUserID: "1"}, time.Minute)
	path := filepath.Join(s.Dir(), id+".session")
	os.WriteFile(path, []byte("{not json"), 0o600)
	if _, err := s.Get(ctx, id); err == nil || errors.Is(err, passport.ErrSessionNotFound) {
		t.Fatalf("corrupted session: %v", err)
	}
	// A read error is not "not logged in".
	os.Remove(path)
	os.Mkdir(path, 0o700)
	if _, err := s.Get(ctx, id); err == nil || errors.Is(err, passport.ErrSessionNotFound) {
		t.Fatalf("read error must not look like a missing session: %v", err)
	}
	os.Remove(path)
	// A directory that disappeared.
	os.RemoveAll(s.Dir())
	if _, err := s.Create(ctx, &passport.Identity{}, time.Minute); err == nil {
		t.Error("Create into a missing directory must fail")
	}
	if _, err := s.Cleanup(ctx); err == nil {
		t.Error("Cleanup of a missing directory must fail")
	}
}

func TestCleanup(t *testing.T) {
	s := newStore(t)
	now := time.Now()
	s.now = func() time.Time { return now }
	keep, _ := s.Create(ctx, &passport.Identity{ProviderUserID: "keep"}, time.Hour)
	for i := 0; i < 3; i++ {
		s.Create(ctx, &passport.Identity{ProviderUserID: "old"}, time.Minute)
	}
	os.WriteFile(filepath.Join(s.Dir(), "notes.txt"), []byte("not a session"), 0o600)
	stale := filepath.Join(s.Dir(), keep+".tmp-123")
	os.WriteFile(stale, nil, 0o600)
	os.Chtimes(stale, now.Add(-2*time.Hour), now.Add(-2*time.Hour))
	fresh := filepath.Join(s.Dir(), keep+".tmp-456")
	os.WriteFile(fresh, nil, 0o600)
	os.Chtimes(fresh, now, now)

	now = now.Add(2 * time.Minute)
	n, err := s.Cleanup(ctx)
	if err != nil || n != 3 {
		t.Fatalf("Cleanup = %d, %v; want 3", n, err)
	}
	if _, err := s.Get(ctx, keep); err != nil {
		t.Fatalf("live session removed: %v", err)
	}
	for path, want := range map[string]bool{stale: false, fresh: true, filepath.Join(s.Dir(), "notes.txt"): true} {
		if _, err := os.Stat(path); (err == nil) != want {
			t.Errorf("%s exists = %v, want %v", filepath.Base(path), err == nil, want)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.Cleanup(cancelled); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled Cleanup: %v", err)
	}
}

// Create sweeps expired sessions now and then, so unread ones do not pile up.
func TestSweepOnCreate(t *testing.T) {
	s := newStore(t)
	now := time.Now()
	s.now = func() time.Time { return now }
	for i := 0; i < sweepEvery-1; i++ {
		if _, err := s.Create(ctx, &passport.Identity{}, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(time.Hour)
	if _, err := s.Create(ctx, &passport.Identity{}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(s.Dir()); len(entries) != 1 {
		t.Fatalf("%d files after the sweep, want 1", len(entries))
	}
}
