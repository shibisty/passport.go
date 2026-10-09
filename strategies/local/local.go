// Package local implements login with email and password, like passport-local.
// gtr package: passport-local.
//
// The strategy knows nothing about your users table: you pass a
// VerifyFunc that looks up the user (e.g. via orm.Repository)
// and checks the password (passport/passwordhash).
package local

import (
	"context"
	"strings"

	"passport"
)

// VerifyFunc looks up a user by email and checks the password. If they do not
// match, return passport.ErrInvalidCredentials (without saying what exactly
// was wrong, so as not to reveal whether the email is registered).
type VerifyFunc func(ctx context.Context, email, password string) (*passport.Identity, error)

// ErrInvalidCredentials is the same as passport.ErrInvalidCredentials.
var ErrInvalidCredentials = passport.ErrInvalidCredentials

// Strategy implements passport.CredentialStrategy.
type Strategy struct {
	verify     VerifyFunc
	emailField string
	passField  string
}

// Option changes strategy settings.
type Option func(*Strategy)

// WithFields sets the field names in credentials (default: "email" and "password").
func WithFields(login, password string) Option {
	return func(s *Strategy) { s.emailField, s.passField = login, password }
}

// New creates the "local" strategy.
func New(verify VerifyFunc, opts ...Option) *Strategy {
	s := &Strategy{verify: verify, emailField: "email", passField: "password"}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Name — "local".
func (s *Strategy) Name() string { return "local" }

// Authenticate expects credentials = {"email": "...", "password": "..."}.
// The email is trimmed of surrounding whitespace; the password is passed as is.
func (s *Strategy) Authenticate(ctx context.Context, credentials map[string]string) (*passport.Identity, error) {
	email := strings.TrimSpace(credentials[s.emailField])
	password := credentials[s.passField]
	if email == "" || password == "" {
		return nil, passport.ErrInvalidCredentials
	}
	id, err := s.verify(ctx, email, password)
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, passport.ErrInvalidCredentials
	}
	if id.Provider == "" {
		id.Provider = "local"
	}
	return id, nil
}

var _ passport.CredentialStrategy = (*Strategy)(nil)
