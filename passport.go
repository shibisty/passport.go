// Package passport provides passport.js-style authentication: a shared Authenticator
// and independent strategy packages (local, google, facebook, any OAuth2).
//
// As in passport.js, two questions are split across separate interfaces:
//
//  1. "Who are you?" (login) — Strategy: CredentialStrategy (username and password) or
//     RedirectStrategy (OAuth2: Google, Facebook…).
//  2. "Are you still you?" (subsequent requests) — SessionStore (cookie sessions) or
//     TokenIssuer (JWT), regardless of which strategy was used to log in.
//
// Packages in the family: passport (this one), passport-local, passport-oauth2,
// passport-google, passport-facebook, passport-session-redis.
package passport

import (
	"context"
	"errors"
	"time"
)

// Identity is the result of a successful authentication, the same for all
// strategies. It is the equivalent of req.user in passport.js.
type Identity struct {
	Provider       string `json:"provider"`         // "local", "google", "facebook"…
	ProviderUserID string `json:"provider_user_id"` // ID at the provider (sub/id), or the ID in your DB for local
	Email          string `json:"email"`
	// EmailVerified reports whether the provider confirmed that the email belongs to the user.
	// Link accounts by email only when EmailVerified == true; otherwise an
	// attacker could take over someone else's account by setting their email at the provider.
	EmailVerified bool           `json:"email_verified"`
	Name          string         `json:"name"`
	AvatarURL     string         `json:"avatar_url,omitempty"`
	Raw           map[string]any `json:"-"` // provider profile; never stored in the session or JWT
}

// Strategy is the common strategy marker.
type Strategy interface {
	// Name is the identifier: "local", "google", "facebook"…
	Name() string
}

// CredentialStrategy logs in with directly supplied credentials (username/password,
// API key). It is the equivalent of passport-local.
type CredentialStrategy interface {
	Strategy
	Authenticate(ctx context.Context, credentials map[string]string) (*Identity, error)
}

// RedirectStrategy logs in via a redirect to the provider (OAuth2/OIDC).
type RedirectStrategy interface {
	Strategy
	// AuthCodeURL returns the URL to send the user to. state is a CSRF token;
	// httpauth.NewState / httpauth.CheckState generate and verify it.
	AuthCodeURL(state string) string
	// Callback completes the login using the callback request parameters
	// (usually {"code": "...", "state": "..."} from the query string).
	Callback(ctx context.Context, params map[string]string) (*Identity, error)
}

// SessionStore stores an Identity under a random session ID (usually in a cookie).
type SessionStore interface {
	Create(ctx context.Context, identity *Identity, ttl time.Duration) (sessionID string, err error)
	// Get returns ErrSessionNotFound if the session does not exist or has expired;
	// other errors (e.g. the store being unavailable) are returned as is.
	Get(ctx context.Context, sessionID string) (*Identity, error)
	Destroy(ctx context.Context, sessionID string) error
}

// TokenIssuer issues and verifies self-contained tokens (JWT).
type TokenIssuer interface {
	Issue(ctx context.Context, identity *Identity, ttl time.Duration) (token string, err error)
	Verify(ctx context.Context, token string) (*Identity, error)
}

var (
	ErrStrategyNotFound        = errors.New("passport: strategy not registered")
	ErrUnsupportedStrategyType = errors.New("passport: strategy does not support this login method")
	ErrSessionNotFound         = errors.New("passport: session not found or expired")
	ErrNoSessionStore          = errors.New("passport: SessionStore not configured (Authenticator.UseSessionStore)")
	ErrNoTokenIssuer           = errors.New("passport: TokenIssuer not configured (Authenticator.UseTokenIssuer)")
	// ErrInvalidCredentials means the login credentials are wrong. Strategies return it
	// (or wrap it) so the handler can respond with 401 without revealing the reason.
	ErrInvalidCredentials = errors.New("passport: invalid credentials")
)
