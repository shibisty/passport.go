package local_test

import (
	"context"
	"errors"
	"testing"

	"passport"
	local "passport-local"
)

var errDB = errors.New("db down")

func verify(_ context.Context, email, password string) (*passport.Identity, error) {
	switch {
	case email == "ann@x" && password == " secret ":
		return &passport.Identity{ProviderUserID: "1", Email: email}, nil
	case email == "nil@x":
		return nil, nil
	case email == "db@x":
		return nil, errDB
	case email == "custom@x":
		return &passport.Identity{Provider: "ldap", ProviderUserID: "2"}, nil
	default:
		return nil, local.ErrInvalidCredentials
	}
}

func TestAuthenticate(t *testing.T) {
	s := local.New(verify)
	ctx := context.Background()
	id, err := s.Authenticate(ctx, map[string]string{"email": "  ann@x ", "password": " secret "})
	if err != nil || id.Provider != "local" || id.ProviderUserID != "1" {
		t.Fatalf("got %+v, %v (email trimmed, password as is)", id, err)
	}
	if id, _ := s.Authenticate(ctx, map[string]string{"email": "custom@x", "password": "p"}); id.Provider != "ldap" {
		t.Fatal("Provider set by VerifyFunc must be kept")
	}
	for name, creds := range map[string]map[string]string{
		"empty email":    {"password": "p"},
		"empty password": {"email": "ann@x"},
		"spaces email":   {"email": "  ", "password": "p"},
		"wrong":          {"email": "ann@x", "password": "nope"},
		"nil identity":   {"email": "nil@x", "password": "p"},
	} {
		if _, err := s.Authenticate(ctx, creds); !errors.Is(err, passport.ErrInvalidCredentials) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if _, err := s.Authenticate(ctx, map[string]string{"email": "db@x", "password": "p"}); !errors.Is(err, errDB) {
		t.Errorf("internal errors must pass through: %v", err)
	}
	if s.Name() != "local" {
		t.Error("Name")
	}
}

func TestWithFields(t *testing.T) {
	s := local.New(verify, local.WithFields("login", "pass"))
	id, err := s.Authenticate(context.Background(), map[string]string{"login": "ann@x", "pass": " secret "})
	if err != nil || id.ProviderUserID != "1" {
		t.Fatalf("custom fields: %+v, %v", id, err)
	}
}
