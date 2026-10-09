package passport

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Authenticator is the central entry point, the equivalent of the passport object.
//
//	a := passport.New().
//		UseSessionStore(memorystore.New()).
//		UseTokenIssuer(issuer) // jwt.New(secret, "myapp")
//	a.Use(local.New(verify))
//	a.Use(google.New(clientID, secret, redirectURL))
//
//	identity, err := a.Credential(ctx, "local", map[string]string{"email": e, "password": p})
//	sessionID, err := a.StartSession(ctx, identity, 24*time.Hour)
//	token, err := a.IssueToken(ctx, identity, time.Hour)
//
// All methods are safe for concurrent use.
type Authenticator struct {
	mu         sync.RWMutex
	strategies map[string]Strategy
	sessions   SessionStore
	tokens     TokenIssuer
}

// New creates an empty Authenticator.
func New() *Authenticator {
	return &Authenticator{strategies: map[string]Strategy{}}
}

// Use registers a strategy under its Name(); registering again replaces it.
func (a *Authenticator) Use(s Strategy) *Authenticator {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.strategies[s.Name()] = s
	return a
}

// UseSessionStore sets the session store.
func (a *Authenticator) UseSessionStore(s SessionStore) *Authenticator {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessions = s
	return a
}

// UseTokenIssuer sets the token issuer.
func (a *Authenticator) UseTokenIssuer(t TokenIssuer) *Authenticator {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tokens = t
	return a
}

func (a *Authenticator) strategy(name string) (Strategy, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	s, ok := a.strategies[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrStrategyNotFound, name)
	}
	return s, nil
}

func (a *Authenticator) sessionStore() (SessionStore, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.sessions == nil {
		return nil, ErrNoSessionStore
	}
	return a.sessions, nil
}

func (a *Authenticator) tokenIssuer() (TokenIssuer, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.tokens == nil {
		return nil, ErrNoTokenIssuer
	}
	return a.tokens, nil
}

// Credential logs in via a CredentialStrategy (local, etc.).
func (a *Authenticator) Credential(ctx context.Context, strategyName string, credentials map[string]string) (*Identity, error) {
	s, err := a.strategy(strategyName)
	if err != nil {
		return nil, err
	}
	cs, ok := s.(CredentialStrategy)
	if !ok {
		return nil, fmt.Errorf("%w: %q logs in via redirect — use RedirectURL and Callback", ErrUnsupportedStrategyType, strategyName)
	}
	return cs.Authenticate(ctx, credentials)
}

// RedirectURL returns the URL that starts an OAuth2 login (google, facebook…).
func (a *Authenticator) RedirectURL(strategyName, state string) (string, error) {
	rs, err := a.redirect(strategyName)
	if err != nil {
		return "", err
	}
	return rs.AuthCodeURL(state), nil
}

// Callback completes an OAuth2 login using the callback request parameters.
// Check state before calling it (httpauth.CheckState).
func (a *Authenticator) Callback(ctx context.Context, strategyName string, params map[string]string) (*Identity, error) {
	rs, err := a.redirect(strategyName)
	if err != nil {
		return nil, err
	}
	return rs.Callback(ctx, params)
}

func (a *Authenticator) redirect(name string) (RedirectStrategy, error) {
	s, err := a.strategy(name)
	if err != nil {
		return nil, err
	}
	rs, ok := s.(RedirectStrategy)
	if !ok {
		return nil, fmt.Errorf("%w: %q logs in with username and password — use Credential", ErrUnsupportedStrategyType, name)
	}
	return rs, nil
}

// StartSession creates a session and returns its ID.
func (a *Authenticator) StartSession(ctx context.Context, identity *Identity, ttl time.Duration) (string, error) {
	s, err := a.sessionStore()
	if err != nil {
		return "", err
	}
	return s.Create(ctx, identity, ttl)
}

// VerifySession returns the session's Identity or ErrSessionNotFound.
func (a *Authenticator) VerifySession(ctx context.Context, sessionID string) (*Identity, error) {
	s, err := a.sessionStore()
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, sessionID)
}

// EndSession deletes the session (logout).
func (a *Authenticator) EndSession(ctx context.Context, sessionID string) error {
	s, err := a.sessionStore()
	if err != nil {
		return err
	}
	return s.Destroy(ctx, sessionID)
}

// IssueToken issues a token for identity.
func (a *Authenticator) IssueToken(ctx context.Context, identity *Identity, ttl time.Duration) (string, error) {
	t, err := a.tokenIssuer()
	if err != nil {
		return "", err
	}
	return t.Issue(ctx, identity, ttl)
}

// VerifyToken verifies a token and returns its Identity.
func (a *Authenticator) VerifyToken(ctx context.Context, token string) (*Identity, error) {
	t, err := a.tokenIssuer()
	if err != nil {
		return nil, err
	}
	return t.Verify(ctx, token)
}
