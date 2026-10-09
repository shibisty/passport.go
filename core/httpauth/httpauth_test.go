package httpauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"passport"
	"passport/memorystore"
)

type tokens struct{}

func (tokens) Issue(context.Context, *passport.Identity, time.Duration) (string, error) {
	return "", nil
}
func (tokens) Verify(_ context.Context, tok string) (*passport.Identity, error) {
	if tok == "good" {
		return &passport.Identity{ProviderUserID: "token-user"}, nil
	}
	return nil, errors.New("bad")
}

func setup(t *testing.T) (*passport.Authenticator, string, http.Handler) {
	t.Helper()
	a := passport.New().UseSessionStore(memorystore.New()).UseTokenIssuer(tokens{})
	sid, err := a.StartSession(context.Background(), &passport.Identity{ProviderUserID: "session-user"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	h := Middleware(a)(RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _ := FromContext(r.Context())
		w.Write([]byte(id.ProviderUserID))
	})))
	return a, sid, h
}

func TestMiddleware(t *testing.T) {
	_, sid, h := setup(t)
	cases := []struct {
		name   string
		auth   string
		cookie string
		code   int
		body   string
	}{
		{"bearer", "Bearer good", "", 200, "token-user"},
		{"bearer lowercase scheme", "bearer good", "", 200, "token-user"},
		{"bad bearer falls back to cookie", "Bearer bad", sid, 200, "session-user"},
		{"cookie", "", sid, 200, "session-user"},
		{"unknown cookie", "", "nope", 401, ""},
		{"empty bearer", "Bearer ", "", 401, ""},
		{"basic auth ignored", "Basic Zm9vOmJhcg==", "", 401, ""},
		{"nothing", "", "", 401, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/me", nil)
			if tc.auth != "" {
				r.Header.Set("Authorization", tc.auth)
			}
			if tc.cookie != "" {
				r.AddCookie(&http.Cookie{Name: CookieName, Value: tc.cookie})
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.code || (tc.body != "" && w.Body.String() != tc.body) {
				t.Fatalf("got %d %q, want %d %q", w.Code, w.Body.String(), tc.code, tc.body)
			}
		})
	}
}

func TestCookies(t *testing.T) {
	w := httptest.NewRecorder()
	SetSessionCookie(w, "abc", 3600)
	ClearSessionCookie(w)
	set := w.Result().Cookies()
	if len(set) != 2 {
		t.Fatalf("cookies: %v", set)
	}
	c := set[0]
	if c.Name != CookieName || c.Value != "abc" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.MaxAge != 3600 || c.Path != "/" {
		t.Fatalf("session cookie: %+v", c)
	}
	if set[1].MaxAge >= 0 || set[1].Value != "" {
		t.Fatalf("clear cookie: %+v", set[1])
	}
}

func TestState(t *testing.T) {
	w := httptest.NewRecorder()
	state, err := NewState(w)
	if err != nil || len(state) != 64 {
		t.Fatalf("NewState = %q, %v", state, err)
	}
	stateCookie := w.Result().Cookies()[0]
	if stateCookie.Name != StateCookieName || !stateCookie.HttpOnly || stateCookie.MaxAge != stateMaxAge {
		t.Fatalf("state cookie: %+v", stateCookie)
	}

	check := func(query string, withCookie bool) error {
		r := httptest.NewRequest("GET", "/cb?"+query, nil)
		if withCookie {
			r.AddCookie(&http.Cookie{Name: StateCookieName, Value: state})
		}
		w := httptest.NewRecorder()
		err := CheckState(w, r)
		if c := w.Result().Cookies(); len(c) != 1 || c[0].MaxAge >= 0 {
			t.Fatalf("CheckState must clear the state cookie: %v", c)
		}
		return err
	}
	if err := check("state="+state+"&code=x", true); err != nil {
		t.Fatalf("valid state: %v", err)
	}
	for name, err := range map[string]error{
		"wrong state":   check("state=evil", true),
		"no cookie":     check("state="+state, false),
		"no parameter":  check("code=x", true),
		"prefix attack": check("state="+strings.TrimSuffix(state, state[60:]), true),
	} {
		if !errors.Is(err, ErrBadState) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestWithIdentity(t *testing.T) {
	ctx := WithIdentity(context.Background(), &passport.Identity{Name: "x"})
	if id, ok := FromContext(ctx); !ok || id.Name != "x" {
		t.Fatal("WithIdentity/FromContext")
	}
	if _, ok := FromContext(context.Background()); ok {
		t.Fatal("empty context")
	}
}
