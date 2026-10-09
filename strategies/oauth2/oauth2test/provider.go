// Package oauth2test provides a fake httptest-based OAuth2 provider for testing
// strategies (passport-google, passport-facebook, your own).
//
//	p := oauth2test.NewProvider(t, map[string]any{"sub": "42", "email": "a@x"})
//	cfg.TokenURL, cfg.UserInfoURL = p.TokenURL(), p.UserInfoURL()
//	identity, err := strategy.Callback(ctx, map[string]string{"code": p.Code})
package oauth2test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// Provider is a fake provider. It accepts only Code, ClientID and
// ClientSecret, issues AccessToken and serves Profile for it.
type Provider struct {
	Code         string
	ClientID     string
	ClientSecret string
	AccessToken  string
	Profile      map[string]any

	// TokenStatus/UserInfoStatus set the response status (200 by default), for testing errors.
	TokenStatus    int
	UserInfoStatus int
	// TokenBody/UserInfoBody set a raw response body instead of normal JSON.
	TokenBody    string
	UserInfoBody string

	mu       sync.Mutex
	requests []*http.Request
	server   *httptest.Server
}

// NewProvider starts the provider; it stops when the test ends.
func NewProvider(t testing.TB, profile map[string]any) *Provider {
	p := &Provider{
		Code: "test-code", ClientID: "client-id", ClientSecret: "client-secret",
		AccessToken: "test-access-token", Profile: profile,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", p.token)
	mux.HandleFunc("/userinfo", p.userinfo)
	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

// AuthURL, TokenURL, UserInfoURL return the endpoints for oauth2.Config.
func (p *Provider) AuthURL() string     { return p.server.URL + "/authorize" }
func (p *Provider) TokenURL() string    { return p.server.URL + "/token" }
func (p *Provider) UserInfoURL() string { return p.server.URL + "/userinfo" }

// Requests returns the received requests (for assertions).
func (p *Provider) Requests() []*http.Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*http.Request(nil), p.requests...)
}

func (p *Provider) record(r *http.Request) {
	p.mu.Lock()
	p.requests = append(p.requests, r)
	p.mu.Unlock()
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	p.record(r)
	if p.TokenStatus != 0 {
		w.WriteHeader(p.TokenStatus)
	}
	if p.TokenBody != "" {
		w.Write([]byte(p.TokenBody))
		return
	}
	if err := r.ParseForm(); err != nil || r.Method != http.MethodPost ||
		r.PostForm.Get("grant_type") != "authorization_code" ||
		r.PostForm.Get("code") != p.Code ||
		r.PostForm.Get("client_id") != p.ClientID ||
		r.PostForm.Get("client_secret") != p.ClientSecret {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"access_token": p.AccessToken, "token_type": "Bearer", "expires_in": 3600})
}

func (p *Provider) userinfo(w http.ResponseWriter, r *http.Request) {
	p.record(r)
	if p.UserInfoStatus != 0 {
		w.WriteHeader(p.UserInfoStatus)
	}
	if p.UserInfoBody != "" {
		w.Write([]byte(p.UserInfoBody))
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+p.AccessToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	json.NewEncoder(w).Encode(p.Profile)
}
