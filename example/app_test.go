package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"passport"
	"passport-google"
	"passport-local"
	"passport-oauth2/oauth2test"
	"passport/httpauth"
	"passport/jwt"
	"passport/memorystore"
	"passport/passwordhash"
)

type testApp struct {
	srv    *httptest.Server
	client *http.Client
	google *oauth2test.Provider
}

func newTestApp(t *testing.T, find FindUserFunc) *testApp {
	t.Helper()
	tokens, err := jwt.New(strings.Repeat("k", 32), "test")
	if err != nil {
		t.Fatal(err)
	}
	p := oauth2test.NewProvider(t, map[string]any{"sub": "g-1", "email": "ann@gmail.com", "email_verified": true, "name": "Ann G"})
	a := passport.New().
		UseSessionStore(memorystore.New()).
		UseTokenIssuer(tokens).
		Use(local.New(verifyPassword(find))).
		Use(google.New(p.ClientID, p.ClientSecret, "https://app/auth/google/callback",
			google.WithEndpoints(p.AuthURL(), p.TokenURL(), p.UserInfoURL())))
	srv := httptest.NewTLSServer(newMux(a, "google")) // Secure cookies require https
	t.Cleanup(srv.Close)
	client := srv.Client()
	client.Jar, _ = cookiejar.New(nil)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &testApp{srv: srv, client: client, google: p}
}

func (a *testApp) do(t *testing.T, method, path, body, bearer string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, a.srv.URL+path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

var annHash = func() string { h, _ := passwordhash.Hash("correct horse"); return h }()

func noUsers(context.Context, string) (*User, error) { return nil, nil }

func findAnn(_ context.Context, email string) (*User, error) {
	if email == "ann@example.com" {
		return &User{ID: 7, Email: email, Name: "Ann", PasswordHash: annHash}, nil
	}
	return nil, nil
}

func TestPasswordLoginSessionAndToken(t *testing.T) {
	app := newTestApp(t, findAnn)

	if r := app.do(t, "GET", "/me", "", ""); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/me before login: %d", r.StatusCode)
	}
	for _, body := range []string{`{"email":"ann@example.com","password":"wrong"}`, `{"email":"bob@example.com","password":"x"}`, `{"email":"","password":""}`} {
		if r := app.do(t, "POST", "/login/password", body, ""); r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s: %d", body, r.StatusCode)
		}
	}
	if r := app.do(t, "POST", "/login/password", "{", ""); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad json: %d", r.StatusCode)
	}

	r := app.do(t, "POST", "/login/password", `{"email":" ann@example.com ","password":"correct horse"}`, "")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	var out struct{ Token string }
	json.NewDecoder(r.Body).Decode(&out)

	me := func(bearer string) (int, passport.Identity) {
		r := app.do(t, "GET", "/me", "", bearer)
		var id passport.Identity
		json.NewDecoder(r.Body).Decode(&id)
		return r.StatusCode, id
	}
	if code, id := me(""); code != 200 || id.ProviderUserID != "7" || id.Email != "ann@example.com" {
		t.Fatalf("/me by cookie: %d %+v", code, id)
	}

	if r := app.do(t, "POST", "/logout", "", ""); r.StatusCode != http.StatusNoContent {
		t.Fatalf("logout: %d", r.StatusCode)
	}
	if code, _ := me(""); code != http.StatusUnauthorized {
		t.Fatalf("/me after logout: %d", code)
	}
	// The JWT lives independently of the cookie session.
	if code, id := me(out.Token); code != 200 || id.Name != "Ann" {
		t.Fatalf("/me by bearer: %d %+v", code, id)
	}
	if code, _ := me(out.Token + "x"); code != http.StatusUnauthorized {
		t.Fatalf("tampered token: %d", code)
	}
}

func TestDatabaseErrorIsNotInvalidCredentials(t *testing.T) {
	app := newTestApp(t, func(context.Context, string) (*User, error) { return nil, errors.New("db down") })
	if r := app.do(t, "POST", "/login/password", `{"email":"a@b","password":"x"}`, ""); r.StatusCode != http.StatusInternalServerError {
		t.Fatalf("db error: %d", r.StatusCode)
	}
}

func TestGoogleLogin(t *testing.T) {
	app := newTestApp(t, noUsers)

	r := app.do(t, "GET", "/auth/google", "", "")
	if r.StatusCode != http.StatusFound {
		t.Fatalf("redirect: %d", r.StatusCode)
	}
	loc, _ := url.Parse(r.Header.Get("Location"))
	state := loc.Query().Get("state")
	if !strings.HasPrefix(loc.String(), app.google.AuthURL()) || len(state) < 32 {
		t.Fatalf("location: %s", loc)
	}

	// A foreign state (CSRF) is rejected, and the state cookie is deleted afterwards.
	if r := app.do(t, "GET", "/auth/google/callback?code="+app.google.Code+"&state=forged", "", ""); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("forged state: %d", r.StatusCode)
	}
	if r := app.do(t, "GET", "/auth/google/callback?code="+app.google.Code+"&state="+state, "", ""); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("state must be single-use: %d", r.StatusCode)
	}

	// Legitimate login.
	r = app.do(t, "GET", "/auth/google", "", "")
	loc, _ = url.Parse(r.Header.Get("Location"))
	state = loc.Query().Get("state")
	r = app.do(t, "GET", "/auth/google/callback?code="+app.google.Code+"&state="+url.QueryEscape(state), "", "")
	if r.StatusCode != http.StatusFound || r.Header.Get("Location") != "/me" {
		t.Fatalf("callback: %d %s", r.StatusCode, r.Header.Get("Location"))
	}
	r = app.do(t, "GET", "/me", "", "")
	var id passport.Identity
	json.NewDecoder(r.Body).Decode(&id)
	if id.Provider != "google" || id.ProviderUserID != "g-1" || !id.EmailVerified {
		t.Fatalf("identity: %+v", id)
	}

	// The user declined at the provider.
	r = app.do(t, "GET", "/auth/google", "", "")
	loc, _ = url.Parse(r.Header.Get("Location"))
	if r := app.do(t, "GET", "/auth/google/callback?error=access_denied&state="+url.QueryEscape(loc.Query().Get("state")), "", ""); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("access denied: %d", r.StatusCode)
	}
}

func TestCookiesAreSecure(t *testing.T) {
	app := newTestApp(t, findAnn)
	r := app.do(t, "POST", "/login/password", `{"email":"ann@example.com","password":"correct horse"}`, "")
	for _, c := range r.Cookies() {
		if c.Name == httpauth.CookieName && (!c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode) {
			t.Fatalf("session cookie flags: %+v", c)
		}
	}
}
