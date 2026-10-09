package facebook_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	facebook "passport-facebook"
	"passport-oauth2/oauth2test"
)

func TestCallback(t *testing.T) {
	p := oauth2test.NewProvider(t, map[string]any{
		"id": "10158", "email": "ann@fb.com", "name": "Ann",
		"picture": map[string]any{"data": map[string]any{"url": "https://fb/a.jpg"}},
	})
	s := facebook.New(p.ClientID, p.ClientSecret, "https://app/cb", facebook.WithEndpoints(p.AuthURL(), p.TokenURL(), p.UserInfoURL()))
	id, err := s.Callback(context.Background(), map[string]string{"code": p.Code})
	if err != nil {
		t.Fatal(err)
	}
	if id.Provider != "facebook" || id.ProviderUserID != "10158" || id.Email != "ann@fb.com" || id.EmailVerified || id.AvatarURL != "https://fb/a.jpg" {
		t.Fatalf("identity = %+v", *id)
	}
}

func TestVersionAndOptions(t *testing.T) {
	cfg := facebook.New("app", "sec", "cb").Config()
	for _, u := range []string{cfg.AuthURL, cfg.TokenURL, cfg.UserInfoURL} {
		if !strings.Contains(u, "/"+facebook.DefaultAPIVersion+"/") {
			t.Errorf("default version not in %s", u)
		}
	}
	if !strings.HasSuffix(cfg.UserInfoURL, "/me?fields=id%2Cname%2Cemail%2Cpicture") {
		t.Errorf("userinfo URL: %s", cfg.UserInfoURL)
	}
	if facebook.DefaultAPIVersion == "v19.0" {
		t.Error("v19.0 expired on 2026-05-21")
	}

	client := &http.Client{}
	s := facebook.New("app", "sec", "cb", facebook.WithAPIVersion("v25.0"), facebook.WithScopes("email"), facebook.WithHTTPClient(client))
	cfg = s.Config()
	if !strings.Contains(cfg.TokenURL, "/v25.0/") || len(cfg.Scopes) != 1 || cfg.HTTPClient != client || s.Name() != "facebook" {
		t.Fatalf("options: %+v", cfg)
	}
}

func TestNoPicture(t *testing.T) {
	id, _ := facebook.MapProfile(map[string]any{"id": "1", "picture": "not-an-object"})
	if id.AvatarURL != "" || id.ProviderUserID != "1" {
		t.Fatalf("%+v", *id)
	}
}
