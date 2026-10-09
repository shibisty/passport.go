// Package memorystore implements an in-process, in-memory passport.SessionStore.
// Suitable for development, tests and single-process applications;
// to keep sessions across restarts use passport-session-file, for multiple
// instances passport-session-redis.
package memorystore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"passport"
)

// sweepEvery is how many session creations happen between sweeps of expired sessions, so that
// memory does not grow without bound from sessions that are never accessed again.
const sweepEvery = 256

type entry struct {
	identity passport.Identity
	expires  time.Time
}

// Store implements passport.SessionStore.
type Store struct {
	mu      sync.Mutex
	items   map[string]entry
	created int
	now     func() time.Time
}

// New creates an empty store.
func New() *Store {
	return &Store{items: map[string]entry{}, now: time.Now}
}

// Create creates a session with an ID of 32 random bytes (hex).
func (s *Store) Create(_ context.Context, identity *passport.Identity, ttl time.Duration) (string, error) {
	id, err := NewID()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.items[id] = entry{identity: *identity, expires: now.Add(ttl)}
	s.created++
	if s.created%sweepEvery == 0 {
		for k, e := range s.items {
			if !now.Before(e.expires) {
				delete(s.items, k)
			}
		}
	}
	return id, nil
}

// Get returns a copy of the Identity or passport.ErrSessionNotFound.
func (s *Store) Get(_ context.Context, sessionID string) (*passport.Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.items[sessionID]
	if !ok {
		return nil, passport.ErrSessionNotFound
	}
	if !s.now().Before(e.expires) {
		delete(s.items, sessionID)
		return nil, passport.ErrSessionNotFound
	}
	id := e.identity
	return &id, nil
}

// Destroy deletes a session; a missing session is not an error.
func (s *Store) Destroy(_ context.Context, sessionID string) error {
	s.mu.Lock()
	delete(s.items, sessionID)
	s.mu.Unlock()
	return nil
}

// Len returns the number of stored sessions (including expired ones not yet removed).
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

// NewID returns a cryptographically secure session ID: 32 random bytes in hex.
func NewID() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

var _ passport.SessionStore = (*Store)(nil)
