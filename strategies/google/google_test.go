package google_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	google "passport-google"
	"passport-oauth2/oauth2test"
)

func TestCallback(t *testing.T) {
	p := oauth2test.NewProvider(t, map[string]any{
		"sub": "1093", "email": "ann@gmail.com", "email_verified": true, "name": "Ann", "picture": "https://p/a.jpg",
	})
	s := google.New(p.ClientID, p.ClientSecret, "https://app/cb", google.WithEndpoints(p.AuthURL(), p.TokenURL(), p.UserInfoURL()))
	id, err := s.Callback(context.Background(), map[string]string{"code": p.Code})
	if err != nil {
		t.Fatal(err)
	}
	if id.Provider != "google" || id.ProviderUserID != "1093" || id.Email != "ann@gmail.com" || !id.EmailVerified || id.Name != "Ann" || id.AvatarURL != "https://p/a.jpg" {
		t.Fatalf("identity = %+v", *id)
	}
}

func TestUnverifiedEmail(t *testing.T) {
	p := oauth2test.NewProvider(t, map[string]any{"sub": "1", "email": "x@y", "email_verified": false})
	s := google.New(p.ClientID, p.ClientSecret, "cb", google.WithEndpoints(p.AuthURL(), p.TokenURL(), p.UserInfoURL()))
	id, err := s.Callback(context.Background(), map[string]string{"code": p.Code})
	if err != nil || id.EmailVerified {
		t.Fatalf("unverified email must stay unverified: %+v, %v", id, err)
	}
}

func TestDefaultsAndOptions(t *testing.T) {
	client := &http.Client{}
	s := google.New("cid", "sec", "https://app/cb",
		google.WithScopes("openid", "email"), google.WithHTTPClient(client),
		google.WithAuthParam("prompt", "select_account"), google.WithAuthParam("hd", "example.com"))
	cfg := s.Config()
	if cfg.AuthURL != google.AuthURL || cfg.TokenURL != google.TokenURL || cfg.UserInfoURL != google.UserInfoURL {
		t.Fatalf("default endpoints: %+v", cfg)
	}
	if cfg.HTTPClient != client || len(cfg.Scopes) != 2 || s.Name() != "google" {
		t.Fatalf("options: %+v", cfg)
	}
	u, _ := url.Parse(s.AuthCodeURL("st"))
	if q := u.Query(); q.Get("prompt") != "select_account" || q.Get("hd") != "example.com" || q.Get("scope") != "openid email" {
		t.Fatalf("auth URL: %s", u)
	}
	if def := google.New("a", "b", "c").Config(); len(def.Scopes) != 3 {
		t.Fatalf("default scopes: %v", def.Scopes)
	}
}
