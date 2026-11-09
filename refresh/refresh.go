// Package refresh issues refresh tokens that rotate on every use, with reuse
// detection (OAuth 2.0 Security BCP, 4.14):
//
//	refresher := refresh.New(refresh.NewMemoryStore(), 30*24*time.Hour)
//	pair, err := refresher.Issue(ctx, issuer, identity, 15*time.Minute) // access JWT + refresh token
//	pair, err = refresher.Rotate(ctx, issuer, pair.Refresh, 15*time.Minute) // a new pair; the old refresh token is spent
//	err = refresher.Revoke(ctx, pair.Refresh)                           // logout: the whole family
//
// A refresh token is 32 random bytes (base64url); only its SHA-256 is
// stored, so a leaked store does not leak usable tokens. Each Rotate spends
// the token and issues the next one of the same family. Presenting a spent
// token again means it was stolen (or the client replayed it): the whole
// family is revoked, and both the thief and the user must log in again.
package refresh

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"passport"
)

var (
	// ErrInvalid: the token is unknown, expired or revoked.
	ErrInvalid = errors.New("refresh: invalid or expired refresh token")
	// ErrReused: a spent token was presented again; its family is revoked.
	ErrReused = errors.New("refresh: refresh token reused; all tokens of this login were revoked")
	// ErrNotFound is returned by a Store for a missing record.
	ErrNotFound = errors.New("refresh: record not found")
)

// Record is a stored refresh token. ID is the SHA-256 of the token
// (base64url), never the token itself.
type Record struct {
	ID       string            `json:"id"`
	Family   string            `json:"family"` // all tokens of one login
	Identity passport.Identity `json:"identity"`
	Expires  time.Time         `json:"expires"`
	Spent    bool              `json:"spent"`
}

// Store keeps refresh token records (memory here; SQL via orm, Redis).
type Store interface {
	// Save inserts or replaces a record.
	Save(ctx context.Context, r Record) error
	// Get returns ErrNotFound for a missing record.
	Get(ctx context.Context, id string) (*Record, error)
	// Spend marks a record spent and reports whether it was unspent before,
	// atomically: of two concurrent Rotate calls with one token, one wins.
	Spend(ctx context.Context, id string) (bool, error)
	// RevokeFamily deletes every record of a family.
	RevokeFamily(ctx context.Context, family string) error
}

// TokenIssuer is what Issue and Rotate sign access tokens with
// (passport/jwt.Issuer, Authenticator).
type TokenIssuer interface {
	Issue(ctx context.Context, identity *passport.Identity, ttl time.Duration) (string, error)
}

// Pair is what a client gets on login and on refresh.
type Pair struct {
	Access    string    `json:"access_token"`
	Refresh   string    `json:"refresh_token"`
	TokenType string    `json:"token_type"`
	ExpiresIn int       `json:"expires_in"` // seconds of the access token
	Expires   time.Time `json:"-"`          // of the refresh token
}

// Refresher issues and rotates refresh tokens.
type Refresher struct {
	store Store
	ttl   time.Duration
	now   func() time.Time
}

// New makes a Refresher whose refresh tokens live ttl (sliding: each
// rotation starts a new ttl).
func New(store Store, ttl time.Duration) *Refresher {
	return &Refresher{store: store, ttl: ttl, now: time.Now}
}

// WithClock replaces the clock (tests).
func (r *Refresher) WithClock(now func() time.Time) *Refresher { r.now = now; return r }

// Issue starts a login: an access token from issuer and the first refresh
// token of a new family.
func (r *Refresher) Issue(ctx context.Context, issuer TokenIssuer, identity *passport.Identity, accessTTL time.Duration) (Pair, error) {
	family, err := randomToken()
	if err != nil {
		return Pair{}, err
	}
	return r.pair(ctx, issuer, identity, accessTTL, family)
}

// Rotate spends a refresh token and returns a new pair of the same family.
// A spent token revokes the family (ErrReused); an unknown or expired one is
// ErrInvalid.
func (r *Refresher) Rotate(ctx context.Context, issuer TokenIssuer, token string, accessTTL time.Duration) (Pair, error) {
	rec, err := r.store.Get(ctx, hash(token))
	if errors.Is(err, ErrNotFound) {
		return Pair{}, ErrInvalid
	}
	if err != nil {
		return Pair{}, err
	}
	if rec.Spent {
		return Pair{}, r.reused(ctx, rec)
	}
	if !r.now().Before(rec.Expires) {
		return Pair{}, ErrInvalid
	}
	won, err := r.store.Spend(ctx, rec.ID)
	if err != nil {
		return Pair{}, err
	}
	if !won { // spent concurrently by another request with the same token
		return Pair{}, r.reused(ctx, rec)
	}
	id := rec.Identity
	return r.pair(ctx, issuer, &id, accessTTL, rec.Family)
}

func (r *Refresher) reused(ctx context.Context, rec *Record) error {
	if err := r.store.RevokeFamily(ctx, rec.Family); err != nil {
		return fmt.Errorf("%w (revoking the family failed: %v)", ErrReused, err)
	}
	return ErrReused
}

// Revoke ends the login a refresh token belongs to (logout); an unknown
// token is not an error.
func (r *Refresher) Revoke(ctx context.Context, token string) error {
	rec, err := r.store.Get(ctx, hash(token))
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return r.store.RevokeFamily(ctx, rec.Family)
}

func (r *Refresher) pair(ctx context.Context, issuer TokenIssuer, identity *passport.Identity, accessTTL time.Duration, family string) (Pair, error) {
	access, err := issuer.Issue(ctx, identity, accessTTL)
	if err != nil {
		return Pair{}, err
	}
	token, err := randomToken()
	if err != nil {
		return Pair{}, err
	}
	expires := r.now().Add(r.ttl)
	id := *identity
	id.Raw = nil
	if err := r.store.Save(ctx, Record{ID: hash(token), Family: family, Identity: id, Expires: expires}); err != nil {
		return Pair{}, err
	}
	return Pair{Access: access, Refresh: token, TokenType: "Bearer", ExpiresIn: int(accessTTL / time.Second), Expires: expires}, nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// MemoryStore is an in-process Store for tests and single-process apps.
type MemoryStore struct {
	mu      sync.Mutex
	records map[string]Record
}

// NewMemoryStore makes an empty MemoryStore.
func NewMemoryStore() *MemoryStore { return &MemoryStore{records: map[string]Record{}} }

func (m *MemoryStore) Save(_ context.Context, r Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[r.ID] = r
	return nil
}

func (m *MemoryStore) Get(_ context.Context, id string) (*Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[id]
	if !ok {
		return nil, ErrNotFound
	}
	return &r, nil
}

func (m *MemoryStore) Spend(_ context.Context, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[id]
	if !ok || r.Spent {
		return false, nil
	}
	r.Spent = true
	m.records[id] = r
	return true, nil
}

func (m *MemoryStore) RevokeFamily(_ context.Context, family string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, r := range m.records {
		if r.Family == family {
			delete(m.records, id)
		}
	}
	return nil
}

// Len is the number of records (tests).
func (m *MemoryStore) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.records)
}

var _ Store = (*MemoryStore)(nil)
