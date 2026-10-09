// Package httpauth wires passport.Authenticator into net/http: middleware
// that identifies the user by Bearer token or cookie session, session
// cookies, and CSRF protection for OAuth2 login via the state parameter.
package httpauth

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"passport"
	"passport/memorystore"
)

const (
	// CookieName is the cookie holding the session ID.
	CookieName = "session_id"
	// StateCookieName is the cookie holding the OAuth2 state during login via the provider.
	StateCookieName = "oauth_state"
	stateMaxAge     = 10 * 60 // seconds allowed to return from the provider
)

// ErrBadState means the state in the callback did not match the issued one (possibly a CSRF attack,
// or the user spent too long at the provider).
var ErrBadState = errors.New("httpauth: invalid or expired OAuth2 state")

type identityKey struct{}

// FromContext returns the Identity stored by Middleware.
func FromContext(ctx context.Context) (*passport.Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(*passport.Identity)
	return id, ok
}

// WithIdentity stores an Identity in the context (for tests and custom middleware).
func WithIdentity(ctx context.Context, id *passport.Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// Middleware identifies the user:
//  1. by the "Authorization: Bearer <token>" header, if a TokenIssuer is configured;
//  2. by the session_id cookie, if a SessionStore is configured.
//
// If neither succeeds, the request proceeds without an Identity; whether login is required
// is up to the handler (see RequireAuth).
func Middleware(a *passport.Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if token, ok := bearer(r); ok {
				if identity, err := a.VerifyToken(ctx, token); err == nil {
					next.ServeHTTP(w, r.WithContext(WithIdentity(ctx, identity)))
					return
				}
			}
			if cookie, err := r.Cookie(CookieName); err == nil && cookie.Value != "" {
				if identity, err := a.VerifySession(ctx, cookie.Value); err == nil {
					next.ServeHTTP(w, r.WithContext(WithIdentity(ctx, identity)))
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// bearer extracts the token; the "Bearer" scheme is case-insensitive (RFC 6750).
func bearer(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

// RequireAuth responds with 401 if Middleware did not find a user.
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := FromContext(r.Context()); !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SetSessionCookie sets the session cookie: HttpOnly, Secure, SameSite=Lax.
// Browsers accept Secure cookies on http://localhost as well.
func SetSessionCookie(w http.ResponseWriter, sessionID string, maxAgeSeconds int) {
	http.SetCookie(w, cookie(CookieName, sessionID, maxAgeSeconds))
}

// ClearSessionCookie deletes the session cookie (logout).
func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, cookie(CookieName, "", -1))
}

// NewState creates a random state for an OAuth2 login, stores it in a cookie
// for 10 minutes and returns it for RedirectURL:
//
//	state, err := httpauth.NewState(w)
//	url, err := a.RedirectURL("google", state)
func NewState(w http.ResponseWriter) (string, error) {
	state, err := memorystore.NewID()
	if err != nil {
		return "", err
	}
	http.SetCookie(w, cookie(StateCookieName, state, stateMaxAge))
	return state, nil
}

// CheckState compares the state parameter from the callback request with the cookie and deletes
// the cookie (state is single-use). Call it before Authenticator.Callback.
func CheckState(w http.ResponseWriter, r *http.Request) error {
	got := r.URL.Query().Get("state")
	c, err := r.Cookie(StateCookieName)
	http.SetCookie(w, cookie(StateCookieName, "", -1))
	if err != nil || got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(c.Value)) != 1 {
		return ErrBadState
	}
	return nil
}

func cookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	}
}
