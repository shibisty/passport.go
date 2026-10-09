// Package facebook implements login with Facebook (OAuth2 + Graph API /me).
// gtr package: passport-facebook.
//
//	a.Use(facebook.New(appID, appSecret, "https://app.example.com/auth/facebook/callback"))
//
// Graph API versions are retired roughly two years after release
// (v19.0 stopped working on May 21, 2026). DefaultAPIVersion is used by default;
// keep the package up to date or set WithAPIVersion.
//
// Facebook does not report whether the email is verified, so Identity.EmailVerified
// is always false: do not link accounts by a Facebook email without your own verification.
package facebook

import (
	"net/http"
	"net/url"

	"passport"
	oauth2 "passport-oauth2"
)

// DefaultAPIVersion is the default Graph API version (released July 29, 2026).
const DefaultAPIVersion = "v26.0"

type settings struct {
	version string
	cfg     oauth2.Config
	custom  bool // endpoints set via WithEndpoints
}

// Option changes strategy settings.
type Option func(*settings)

// WithAPIVersion sets the Graph API version, e.g. "v25.0".
func WithAPIVersion(v string) Option { return func(s *settings) { s.version = v } }

// WithScopes replaces the set of scopes (default: email, public_profile).
func WithScopes(scopes ...string) Option { return func(s *settings) { s.cfg.Scopes = scopes } }

// WithHTTPClient sets the HTTP client for requests to Facebook.
func WithHTTPClient(h *http.Client) Option { return func(s *settings) { s.cfg.HTTPClient = h } }

// WithEndpoints overrides the endpoints (for tests with oauth2test).
func WithEndpoints(auth, token, userinfo string) Option {
	return func(s *settings) {
		s.cfg.AuthURL, s.cfg.TokenURL, s.cfg.UserInfoURL = auth, token, userinfo
		s.custom = true
	}
}

// New creates the "facebook" strategy. appID and appSecret come from Meta for Developers.
func New(appID, appSecret, redirectURL string, opts ...Option) *oauth2.Strategy {
	s := &settings{version: DefaultAPIVersion, cfg: oauth2.Config{
		ClientID: appID, ClientSecret: appSecret, RedirectURL: redirectURL,
		Scopes: []string{"email", "public_profile"},
	}}
	for _, o := range opts {
		o(s)
	}
	if !s.custom {
		s.cfg.AuthURL = "https://www.facebook.com/" + s.version + "/dialog/oauth"
		s.cfg.TokenURL = "https://graph.facebook.com/" + s.version + "/oauth/access_token"
		s.cfg.UserInfoURL = "https://graph.facebook.com/" + s.version + "/me?" +
			url.Values{"fields": {"id,name,email,picture"}}.Encode()
	}
	return oauth2.New("facebook", s.cfg, MapProfile)
}

// MapProfile parses the Graph API /me?fields=id,name,email,picture response.
func MapProfile(p map[string]any) (*passport.Identity, error) {
	var picture string
	if pic, ok := p["picture"].(map[string]any); ok {
		if data, ok := pic["data"].(map[string]any); ok {
			picture = oauth2.String(data, "url")
		}
	}
	return &passport.Identity{
		ProviderUserID: oauth2.String(p, "id"),
		Email:          oauth2.String(p, "email"),
		EmailVerified:  false,
		Name:           oauth2.String(p, "name"),
		AvatarURL:      picture,
	}, nil
}
