package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"passport"
	"passport-local"
	"passport/httpauth"
	"passport/passwordhash"
)

const (
	sessionTTL = 24 * time.Hour
	tokenTTL   = time.Hour
)

// User is a record from the user store.
type User struct {
	ID           int64
	Email        string
	Name         string
	PasswordHash string
}

// FindUserFunc looks up a user by email; if not found, it returns (nil, nil).
// In main it is an orm.Repository, in tests a map.
type FindUserFunc func(ctx context.Context, email string) (*User, error)

// dummyHash is verified when the user does not exist, so the response takes as long
// as it does for a wrong password and timing cannot reveal
// whether the email is registered.
var dummyHash = func() string {
	h, err := passwordhash.Hash("dummy password for timing equalization")
	if err != nil {
		panic(err)
	}
	return h
}()

// verifyPassword is the VerifyFunc for the local strategy.
func verifyPassword(find FindUserFunc) local.VerifyFunc {
	return func(ctx context.Context, email, password string) (*passport.Identity, error) {
		u, err := find(ctx, email)
		if err != nil {
			return nil, err // a DB error is not a "wrong password"
		}
		hash := dummyHash
		if u != nil {
			hash = u.PasswordHash
		}
		ok, err := passwordhash.Verify(password, hash)
		if u == nil || err != nil || !ok {
			return nil, local.ErrInvalidCredentials
		}
		if passwordhash.NeedsRehash(u.PasswordHash) {
			// Typically: recompute the hash with the current parameters and store it.
			log.Printf("user %d: password hash needs rehash", u.ID)
		}
		return &passport.Identity{
			Provider:       "local",
			ProviderUserID: strconv.FormatInt(u.ID, 10),
			Email:          u.Email,
			EmailVerified:  true,
			Name:           u.Name,
		}, nil
	}
}

// newMux returns the application's HTTP routes. providers are the names of the configured
// OAuth2 strategies ("google", "facebook").
func newMux(a *passport.Authenticator, providers ...string) http.Handler {
	mux := http.NewServeMux()

	// POST /login/password {"email","password"} — cookie session and JWT.
	mux.HandleFunc("POST /login/password", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Email, Password string }
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		identity, err := a.Credential(r.Context(), "local", map[string]string{"email": body.Email, "password": body.Password})
		if errors.Is(err, passport.ErrInvalidCredentials) {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		if err != nil {
			internalError(w, err)
			return
		}
		if !startSession(w, r, a, identity) {
			return
		}
		token, err := a.IssueToken(r.Context(), identity, tokenTTL)
		if err != nil {
			internalError(w, err)
			return
		}
		writeJSON(w, map[string]string{"token": token})
	})

	for _, name := range providers {
		name := name
		// GET /auth/{provider} — redirect to the provider, state in a cookie.
		mux.HandleFunc("GET /auth/"+name, func(w http.ResponseWriter, r *http.Request) {
			state, err := httpauth.NewState(w)
			if err != nil {
				internalError(w, err)
				return
			}
			url, err := a.RedirectURL(name, state)
			if err != nil {
				internalError(w, err)
				return
			}
			http.Redirect(w, r, url, http.StatusFound)
		})
		// GET /auth/{provider}/callback — check state, exchange the code, start a session.
		mux.HandleFunc("GET /auth/"+name+"/callback", func(w http.ResponseWriter, r *http.Request) {
			if err := httpauth.CheckState(w, r); err != nil {
				http.Error(w, "invalid state", http.StatusBadRequest)
				return
			}
			q := r.URL.Query()
			identity, err := a.Callback(r.Context(), name, map[string]string{
				"code": q.Get("code"), "error": q.Get("error"), "error_description": q.Get("error_description"),
			})
			if err != nil {
				log.Printf("%s callback: %v", name, err)
				http.Error(w, "login failed", http.StatusUnauthorized)
				return
			}
			// Typically: find or create a User by (Provider, ProviderUserID).
			// Link accounts by email only when identity.EmailVerified is set.
			if startSession(w, r, a, identity) {
				http.Redirect(w, r, "/me", http.StatusFound)
			}
		})
	}

	// POST /logout — delete the session and the cookie.
	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(httpauth.CookieName); err == nil {
			if err := a.EndSession(r.Context(), c.Value); err != nil {
				internalError(w, err)
				return
			}
		}
		httpauth.ClearSessionCookie(w)
		w.WriteHeader(http.StatusNoContent)
	})

	// GET /me — logged-in users only (cookie or Bearer JWT).
	mux.Handle("GET /me", httpauth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, _ := httpauth.FromContext(r.Context())
		writeJSON(w, identity)
	})))

	return httpauth.Middleware(a)(mux)
}

func startSession(w http.ResponseWriter, r *http.Request, a *passport.Authenticator, identity *passport.Identity) bool {
	id, err := a.StartSession(r.Context(), identity, sessionTTL)
	if err != nil {
		internalError(w, err)
		return false
	}
	httpauth.SetSessionCookie(w, id, int(sessionTTL/time.Second))
	return true
}

func internalError(w http.ResponseWriter, err error) {
	log.Printf("internal error: %v", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
