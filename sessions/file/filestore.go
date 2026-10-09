// Package filestore implements passport.SessionStore on the file system: one
// file per session in a directory. gtr package: passport-session-file.
//
// It needs no database and keeps sessions across restarts. Several processes
// on one machine (or on a shared volume) can use the same directory: a session
// file is written once, atomically, and never changed. For many instances on
// different machines use passport-session-redis.
//
//	sessions, err := filestore.New("var/sessions")
//	a := passport.New().UseSessionStore(sessions)
package filestore

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"passport"
	"passport/memorystore"
)

const (
	ext     = ".session"
	tmpPart = ".tmp-"
	// sweepEvery is how many sessions are created between sweeps of expired
	// files, so sessions that are never read again do not pile up.
	sweepEvery = 256
	// staleTmp is the age after which a temporary file left by a crashed
	// write is removed by a sweep.
	staleTmp = time.Hour
)

// Store implements passport.SessionStore.
type Store struct {
	dir string
	now func() time.Time

	mu      sync.Mutex
	created int
}

// record is the content of a session file.
type record struct {
	Identity passport.Identity `json:"identity"` // Raw is tagged json:"-" and is not stored
	Expires  time.Time         `json:"expires"`
}

// New uses dir for session files, creating it (mode 0700) if needed.
func New(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("filestore: empty directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("filestore: %w", err)
	}
	st, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("filestore: %w", err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("filestore: %s is not a directory", dir)
	}
	return &Store{dir: dir, now: time.Now}, nil
}

// Dir returns the session directory.
func (s *Store) Dir() string { return s.dir }

// Create writes the session to a new file (mode 0600). The file appears
// complete or not at all: it is written under a temporary name and renamed.
func (s *Store) Create(_ context.Context, identity *passport.Identity, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		return "", fmt.Errorf("filestore: TTL must be greater than zero, got %s", ttl)
	}
	id, err := memorystore.NewID()
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(record{Identity: *identity, Expires: s.now().Add(ttl)})
	if err != nil {
		return "", err
	}
	if err := s.write(id, data); err != nil {
		return "", fmt.Errorf("filestore: %w", err)
	}
	s.mu.Lock()
	s.created++
	sweep := s.created%sweepEvery == 0
	s.mu.Unlock()
	if sweep {
		_, _ = s.Cleanup(context.Background())
	}
	return id, nil
}

func (s *Store) write(id string, data []byte) error {
	f, err := os.CreateTemp(s.dir, id+tmpPart+"*") // mode 0600
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path(id)); err != nil {
		return err
	}
	ok = true
	return nil
}

// Get returns a copy of the session's Identity. A missing, expired or
// malformed id is passport.ErrSessionNotFound; a file system error (no
// permission, a broken disk) is returned as is, so it is not mistaken for
// "not logged in". An expired session file is removed.
func (s *Store) Get(_ context.Context, sessionID string) (*passport.Identity, error) {
	if !validID(sessionID) {
		return nil, passport.ErrSessionNotFound
	}
	data, err := os.ReadFile(s.path(sessionID))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, passport.ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("filestore: %w", err)
	}
	var r record
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("filestore: corrupted session %s: %w", s.path(sessionID), err)
	}
	if !s.now().Before(r.Expires) {
		_ = os.Remove(s.path(sessionID))
		return nil, passport.ErrSessionNotFound
	}
	return &r.Identity, nil
}

// Destroy deletes a session; a missing session is not an error.
func (s *Store) Destroy(_ context.Context, sessionID string) error {
	if !validID(sessionID) {
		return nil
	}
	if err := os.Remove(s.path(sessionID)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("filestore: %w", err)
	}
	return nil
}

// Cleanup removes expired sessions and temporary files left by interrupted
// writes, and returns how many sessions it removed. Create calls it every
// 256 sessions; an application with few logins may also call it on a timer.
// Unreadable or corrupted files are left in place.
func (s *Store) Cleanup(ctx context.Context) (int, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return 0, fmt.Errorf("filestore: %w", err)
	}
	now := s.now()
	removed := 0
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		name := e.Name()
		switch {
		case strings.Contains(name, tmpPart):
			if info, err := e.Info(); err == nil && now.Sub(info.ModTime()) > staleTmp {
				_ = os.Remove(filepath.Join(s.dir, name))
			}
		case strings.HasSuffix(name, ext) && validID(strings.TrimSuffix(name, ext)):
			data, err := os.ReadFile(filepath.Join(s.dir, name))
			if err != nil {
				continue
			}
			var r record
			if json.Unmarshal(data, &r) == nil && !now.Before(r.Expires) {
				if os.Remove(filepath.Join(s.dir, name)) == nil {
					removed++
				}
			}
		}
	}
	return removed, nil
}

func (s *Store) path(id string) string { return filepath.Join(s.dir, id+ext) }

// validID accepts only ids this package creates (64 lowercase hex digits),
// so a session id from a cookie can never name another file.
func validID(id string) bool {
	if len(id) != 64 || strings.ToLower(id) != id {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

var _ passport.SessionStore = (*Store)(nil)
