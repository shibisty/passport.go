// Package google implements login with Google (OAuth2 + OpenID Connect userinfo).
// gtr package: passport-google.
//
//	a.Use(google.New(clientID, clientSecret, "https://app.example.com/auth/google/callback"))
//
// Identity.EmailVerified is taken from Google's email_verified. Link
// accounts by email only if it is true.
package google

import (
	"net/http"

	"passport"
	oauth2 "passport-oauth2"
)

// Default Google endpoints.
const (
	AuthURL     = "https://accounts.google.com/o/oauth2/v2/auth"
	TokenURL    = "https://oauth2.googleapis.com/token"
	UserInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"
)

// Option changes strategy settings.
type Option func(*oauth2.Config)

// WithScopes replaces the set of scopes (default: openid, email, profile).
func WithScopes(scopes ...string) Option { return func(c *oauth2.Config) { c.Scopes = scopes } }

// WithHTTPClient sets the HTTP client for requests to Google.
func WithHTTPClient(h *http.Client) Option { return func(c *oauth2.Config) { c.HTTPClient = h } }

// WithEndpoints overrides the endpoints (for tests with oauth2test).
func WithEndpoints(auth, token, userinfo string) Option {
	return func(c *oauth2.Config) { c.AuthURL, c.TokenURL, c.UserInfoURL = auth, token, userinfo }
}

// WithAuthParam adds a parameter to the login URL, for example
// WithAuthParam("prompt", "select_account") or ("hd", "example.com").
func WithAuthParam(key, value string) Option {
	return func(c *oauth2.Config) {
		if c.AuthParams == nil {
			c.AuthParams = map[string][]string{}
		}
		c.AuthParams.Set(key, value)
	}
}

// New creates the "google" strategy. clientID and clientSecret come from the Google Cloud
// Console; redirectURL is your callback, registered there as well.
func New(clientID, clientSecret, redirectURL string, opts ...Option) *oauth2.Strategy {
	cfg := oauth2.Config{
		ClientID: clientID, ClientSecret: clientSecret, RedirectURL: redirectURL,
		AuthURL: AuthURL, TokenURL: TokenURL, UserInfoURL: UserInfoURL,
		Scopes: []string{"openid", "email", "profile"},
	}
	for _, o := range opts {
		o(&cfg)
	}
	return oauth2.New("google", cfg, MapProfile)
}

// MapProfile parses Google's OpenID Connect userinfo profile.
func MapProfile(p map[string]any) (*passport.Identity, error) {
	return &passport.Identity{
		ProviderUserID: oauth2.String(p, "sub"),
		Email:          oauth2.String(p, "email"),
		EmailVerified:  oauth2.Bool(p, "email_verified"),
		Name:           oauth2.String(p, "name"),
		AvatarURL:      oauth2.String(p, "picture"),
	}, nil
}
