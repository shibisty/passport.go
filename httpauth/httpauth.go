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
type guardKey struct{}

// Guards, as in Laravel: how a request was authenticated.
const (
	GuardWeb = "web" // the session cookie
	GuardAPI = "api" // an Authorization: Bearer token
)

// FromContext returns the Identity stored by Middleware.
func FromContext(ctx context.Context) (*passport.Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(*passport.Identity)
	return id, ok
}

// GuardFrom returns the guard that authenticated the request (GuardWeb,
// GuardAPI), or "" if none did.
func GuardFrom(ctx context.Context) string {
	g, _ := ctx.Value(guardKey{}).(string)
	return g
}

// WithIdentity stores an Identity in the context (for tests and custom middleware).
func WithIdentity(ctx context.Context, id *passport.Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

func withGuard(ctx context.Context, id *passport.Identity, guard string) context.Context {
	return context.WithValue(WithIdentity(ctx, id), guardKey{}, guard)
}

// Middleware identifies the user:
//  1. by the "Authorization: Bearer <token>" header, if a TokenIssuer is configured (GuardAPI);
//  2. by the session_id cookie, if a SessionStore is configured (GuardWeb).
//
// If neither succeeds, the request proceeds without an Identity; whether login is required
// is up to the handler (see RequireAuth). Web and API accept only one of the two.
func Middleware(a *passport.Authenticator) func(http.Handler) http.Handler {
	return guarded(a, true, true)
}

// Web is Middleware for browser routes: the session cookie only.
func Web(a *passport.Authenticator) func(http.Handler) http.Handler { return guarded(a, true, false) }

// API is Middleware for API routes: the Bearer token only, so a browser's
// cookie never authenticates an API call (no CSRF on the API).
func API(a *passport.Authenticator) func(http.Handler) http.Handler { return guarded(a, false, true) }

func guarded(a *passport.Authenticator, web, api bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if token, ok := bearer(r); ok && api {
				if identity, err := a.VerifyToken(ctx, token); err == nil {
					next.ServeHTTP(w, r.WithContext(withGuard(ctx, identity, GuardAPI)))
					return
				}
			}
			if cookie, err := r.Cookie(CookieName); err == nil && cookie.Value != "" && web {
				if identity, err := a.VerifySession(ctx, cookie.Value); err == nil {
					next.ServeHTTP(w, r.WithContext(withGuard(ctx, identity, GuardWeb)))
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

// RequireGuard responds with 401 unless the request was authenticated by
// one of the guards: RequireGuard(GuardAPI) under Middleware refuses a
// session cookie on an API route.
func RequireGuard(guards ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			g := GuardFrom(r.Context())
			for _, want := range guards {
				if g == want {
					next.ServeHTTP(w, r)
					return
				}
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		})
	}
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

// NewFormPostState is NewState for providers that return with a POST
// (response_mode=form_post: Apple). A SameSite=Lax cookie is not sent with
// a cross-site POST, so this one is SameSite=None (still Secure and
// HttpOnly, single-use, 10 minutes).
func NewFormPostState(w http.ResponseWriter) (string, error) {
	state, err := memorystore.NewID()
	if err != nil {
		return "", err
	}
	c := cookie(StateCookieName, state, stateMaxAge)
	c.SameSite = http.SameSiteNoneMode
	http.SetCookie(w, c)
	return state, nil
}

// CheckState compares the state parameter from the callback request with the cookie and deletes
// the cookie (state is single-use). Call it before Authenticator.Callback.
func CheckState(w http.ResponseWriter, r *http.Request) error {
	got := r.FormValue("state") // the query, or the body of a form_post callback (Apple)
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
