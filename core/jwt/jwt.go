// Package jwt implements passport.TokenIssuer with JWT (HS256), using only the standard
// library. The format is RFC 7519 compatible (header.payload.signature, base64url).
//
//	issuer, err := jwt.New(os.Getenv("JWT_SECRET"), "myapp")
//
// Verified: the algorithm in the header (HS256 only — switching it to "none" or
// RS256 is rejected), the signature (in constant time), the issuer (iss) and the validity
// period (exp, nbf). Revoking issued tokens is not supported: keep the
// lifetime short and use sessions where immediate logout is required.
package jwt

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"passport"
)

// MinSecretLength is the minimum secret length in bytes (256 bits for HS256).
const MinSecretLength = 32

var (
	ErrWeakSecret     = errors.New("jwt: secret is shorter than 32 bytes — tokens can be brute-forced")
	ErrMalformedToken = errors.New("jwt: malformed token")
	ErrBadAlgorithm   = errors.New("jwt: unsupported algorithm (expected HS256)")
	ErrBadSignature   = errors.New("jwt: invalid signature")
	ErrBadIssuer      = errors.New("jwt: token was issued by a different issuer")
	ErrExpired        = errors.New("jwt: token has expired")
	ErrNotYetValid    = errors.New("jwt: token is not valid yet")
	ErrBadTTL         = errors.New("jwt: token lifetime must be greater than zero")
)

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ,omitempty"`
}

type claims struct {
	Iss           string `json:"iss,omitempty"`
	Sub           string `json:"sub"`
	Provider      string `json:"provider"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	Avatar        string `json:"avatar,omitempty"`
	Iat           int64  `json:"iat"`
	Nbf           int64  `json:"nbf,omitempty"`
	Exp           int64  `json:"exp"`
}

// Issuer implements passport.TokenIssuer.
type Issuer struct {
	secret []byte
	issuer string
	leeway time.Duration
	now    func() time.Time
}

// Option configures an Issuer.
type Option func(*Issuer)

// WithLeeway allows for clock skew between servers when checking exp/nbf.
func WithLeeway(d time.Duration) Option { return func(i *Issuer) { i.leeway = d } }

// WithClock overrides the current time (for tests).
func WithClock(now func() time.Time) Option { return func(i *Issuer) { i.now = now } }

// New creates an Issuer. secret must be at least MinSecretLength bytes; keep it
// in configuration or a secret store, not in code. issuer is written to iss and
// checked by Verify (an empty issuer is not checked).
func New(secret, issuer string, opts ...Option) (*Issuer, error) {
	if len(secret) < MinSecretLength {
		return nil, ErrWeakSecret
	}
	i := &Issuer{secret: []byte(secret), issuer: issuer, now: time.Now}
	for _, o := range opts {
		o(i)
	}
	return i, nil
}

// Issue issues a token with lifetime ttl.
func (i *Issuer) Issue(_ context.Context, identity *passport.Identity, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		return "", ErrBadTTL
	}
	now := i.now()
	c := claims{
		Iss:           i.issuer,
		Sub:           identity.ProviderUserID,
		Provider:      identity.Provider,
		Email:         identity.Email,
		EmailVerified: identity.EmailVerified,
		Name:          identity.Name,
		Avatar:        identity.AvatarURL,
		Iat:           now.Unix(),
		Exp:           now.Add(ttl).Unix(),
	}
	headerJSON, _ := json.Marshal(header{Alg: "HS256", Typ: "JWT"})
	claimsJSON, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signingInput := b64(headerJSON) + "." + b64(claimsJSON)
	return signingInput + "." + b64(sign(i.secret, signingInput)), nil
}

// Verify verifies a token and returns its Identity.
func (i *Issuer) Verify(_ context.Context, token string) (*passport.Identity, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrMalformedToken
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrMalformedToken
	}
	var h header
	if err := json.Unmarshal(headerJSON, &h); err != nil {
		return nil, ErrMalformedToken
	}
	if h.Alg != "HS256" {
		return nil, ErrBadAlgorithm
	}

	gotSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrMalformedToken
	}
	if subtle.ConstantTimeCompare(sign(i.secret, parts[0]+"."+parts[1]), gotSig) != 1 {
		return nil, ErrBadSignature
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrMalformedToken
	}
	var c claims
	if err := json.Unmarshal(claimsJSON, &c); err != nil {
		return nil, ErrMalformedToken
	}
	if i.issuer != "" && c.Iss != i.issuer {
		return nil, ErrBadIssuer
	}
	now := i.now()
	if now.Add(-i.leeway).Unix() >= c.Exp {
		return nil, ErrExpired
	}
	if c.Nbf != 0 && now.Add(i.leeway).Unix() < c.Nbf {
		return nil, ErrNotYetValid
	}

	return &passport.Identity{
		Provider:       c.Provider,
		ProviderUserID: c.Sub,
		Email:          c.Email,
		EmailVerified:  c.EmailVerified,
		Name:           c.Name,
		AvatarURL:      c.Avatar,
	}, nil
}

func sign(secret []byte, data string) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func b64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

var _ passport.TokenIssuer = (*Issuer)(nil)
