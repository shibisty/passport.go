// Package jwt implements passport.TokenIssuer with JWT (HS256), using only the standard
// library. The format is RFC 7519 compatible (header.payload.signature, base64url).
//
//	issuer, err := jwt.New(os.Getenv("JWT_SECRET"), "myapp")
//
// Verify checks, in this order: the size (MaxTokenLength), the header
// (alg exactly HS256 — "none", RS256 and the rest are rejected; typ JWT if
// present; no crit; kid, if present, names a known key), the signature
// (HMAC-SHA256 compared in constant time, with the current key or one from
// WithPreviousSecrets), then the claims: sub present, iss (when the issuer
// is set), aud (WithAudience), exp (required), nbf, and the revocation hook
// (WithRevocation) by jti. No key is ever taken from the token (jku, jwk,
// x5u are ignored), so a token cannot choose its own key.
package jwt

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"passport"
)

// MinSecretLength is the minimum secret length in bytes (256 bits for HS256).
const MinSecretLength = 32

// MaxTokenLength bounds the tokens Verify parses (bytes).
const MaxTokenLength = 8 << 10

var (
	ErrWeakSecret     = errors.New("jwt: secret is shorter than 32 bytes — tokens can be brute-forced")
	ErrMalformedToken = errors.New("jwt: malformed token")
	ErrBadAlgorithm   = errors.New("jwt: unsupported algorithm (expected HS256)")
	ErrBadSignature   = errors.New("jwt: invalid signature")
	ErrBadIssuer      = errors.New("jwt: token was issued by a different issuer")
	ErrExpired        = errors.New("jwt: token has expired")
	ErrNotYetValid    = errors.New("jwt: token is not valid yet")
	ErrBadTTL         = errors.New("jwt: token lifetime must be greater than zero")
	ErrBadType        = errors.New("jwt: not an access token (typ)")
	ErrBadAudience    = errors.New("jwt: token is meant for a different audience")
	ErrMissingSubject = errors.New("jwt: token has no subject (sub)")
	ErrRevoked        = errors.New("jwt: token has been revoked")
	ErrUnknownKey     = errors.New("jwt: token is signed with an unknown key (kid)")
)

type header struct {
	Alg  string          `json:"alg"`
	Typ  string          `json:"typ,omitempty"`
	Kid  string          `json:"kid,omitempty"`
	Crit json.RawMessage `json:"crit,omitempty"`
}

// audience is aud: one string or a list (RFC 7519, 4.1.3).
type audience []string

func (a audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

type claims struct {
	Iss           string   `json:"iss,omitempty"`
	Aud           audience `json:"aud,omitempty"`
	Jti           string   `json:"jti,omitempty"`
	Sub           string   `json:"sub"`
	Provider      string   `json:"provider"`
	Email         string   `json:"email,omitempty"`
	EmailVerified bool     `json:"email_verified,omitempty"`
	Name          string   `json:"name,omitempty"`
	Avatar        string   `json:"avatar,omitempty"`
	Iat           int64    `json:"iat"`
	Nbf           int64    `json:"nbf,omitempty"`
	Exp           int64    `json:"exp"`
}

// Issuer implements passport.TokenIssuer.
type Issuer struct {
	secret   []byte
	kid      string
	previous map[string][]byte // kid → secret, for tokens signed before a rotation
	issuer   string
	audience []string
	leeway   time.Duration
	now      func() time.Time
	revoked  func(ctx context.Context, jti string) (bool, error)
	err      error
}

// Option configures an Issuer.
type Option func(*Issuer)

// WithLeeway allows for clock skew between servers when checking exp/nbf.
func WithLeeway(d time.Duration) Option { return func(i *Issuer) { i.leeway = d } }

// WithClock overrides the current time (for tests).
func WithClock(now func() time.Time) Option { return func(i *Issuer) { i.now = now } }

// WithAudience writes aud into issued tokens and makes Verify accept only
// tokens meant for one of these audiences (a token without aud is
// rejected). Use it when several services share a secret.
func WithAudience(aud ...string) Option { return func(i *Issuer) { i.audience = aud } }

// WithPreviousSecrets keeps verifying tokens signed with older secrets after
// a rotation; new tokens are signed with the current secret only. Tokens
// name their key in kid, derived from the secret (not the secret itself).
func WithPreviousSecrets(secrets ...string) Option {
	return func(i *Issuer) {
		for _, s := range secrets {
			if len(s) < MinSecretLength {
				i.err = ErrWeakSecret
				return
			}
			i.previous[keyID([]byte(s))] = []byte(s)
		}
	}
}

// WithRevocation makes Verify ask revoked(jti) for every token: true rejects
// it with ErrRevoked (a logout list, a "log out everywhere" timestamp in the
// store). Every issued token has a random jti; Identity does not carry it,
// so get it with TokenID.
func WithRevocation(revoked func(ctx context.Context, jti string) (bool, error)) Option {
	return func(i *Issuer) { i.revoked = revoked }
}

// New creates an Issuer. secret must be at least MinSecretLength bytes; keep it
// in configuration or a secret store, not in code. issuer is written to iss and
// checked by Verify (an empty issuer is not checked).
func New(secret, issuer string, opts ...Option) (*Issuer, error) {
	if len(secret) < MinSecretLength {
		return nil, ErrWeakSecret
	}
	i := &Issuer{secret: []byte(secret), kid: keyID([]byte(secret)), previous: map[string][]byte{}, issuer: issuer, now: time.Now}
	for _, o := range opts {
		o(i)
	}
	if i.err != nil {
		return nil, i.err
	}
	if i.leeway < 0 {
		return nil, errors.New("jwt: leeway must not be negative")
	}
	return i, nil
}

// Issue issues a token with lifetime ttl.
func (i *Issuer) Issue(_ context.Context, identity *passport.Identity, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		return "", ErrBadTTL
	}
	if identity == nil || identity.ProviderUserID == "" {
		return "", ErrMissingSubject
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	now := i.now()
	c := claims{
		Iss:           i.issuer,
		Aud:           i.audience,
		Jti:           b64(jti),
		Sub:           identity.ProviderUserID,
		Provider:      identity.Provider,
		Email:         identity.Email,
		EmailVerified: identity.EmailVerified,
		Name:          identity.Name,
		Avatar:        identity.AvatarURL,
		Iat:           now.Unix(),
		Exp:           now.Add(ttl).Unix(),
	}
	headerJSON, _ := json.Marshal(header{Alg: "HS256", Typ: "JWT", Kid: i.kid})
	claimsJSON, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signingInput := b64(headerJSON) + "." + b64(claimsJSON)
	return signingInput + "." + b64(sign(i.secret, signingInput)), nil
}

// Verify verifies a token and returns its Identity.
func (i *Issuer) Verify(ctx context.Context, token string) (*passport.Identity, error) {
	c, err := i.verify(ctx, token)
	if err != nil {
		return nil, err
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

// TokenID verifies a token and returns its jti and expiry: what a
// revocation list stores on logout (until the expiry, then it can go).
func (i *Issuer) TokenID(ctx context.Context, token string) (jti string, expires time.Time, err error) {
	c, err := i.verify(ctx, token)
	if err != nil {
		return "", time.Time{}, err
	}
	return c.Jti, time.Unix(c.Exp, 0), nil
}

func (i *Issuer) verify(ctx context.Context, token string) (*claims, error) {
	if len(token) > MaxTokenLength {
		return nil, ErrMalformedToken
	}
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
	if h.Typ != "" && !strings.EqualFold(h.Typ, "JWT") {
		return nil, ErrBadType
	}
	if len(h.Crit) > 0 { // extensions we would have to understand (RFC 7515, 4.1.11)
		return nil, ErrMalformedToken
	}
	key := i.secret
	if h.Kid != "" && h.Kid != i.kid {
		prev, ok := i.previous[h.Kid]
		if !ok {
			return nil, ErrUnknownKey
		}
		key = prev
	}

	gotSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrMalformedToken
	}
	if subtle.ConstantTimeCompare(sign(key, parts[0]+"."+parts[1]), gotSig) != 1 {
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
	if c.Sub == "" {
		return nil, ErrMissingSubject
	}
	if i.issuer != "" && c.Iss != i.issuer {
		return nil, ErrBadIssuer
	}
	if len(i.audience) > 0 && !intersects(i.audience, c.Aud) {
		return nil, ErrBadAudience
	}
	now := i.now()
	if now.Add(-i.leeway).Unix() >= c.Exp {
		return nil, ErrExpired
	}
	if c.Nbf != 0 && now.Add(i.leeway).Unix() < c.Nbf {
		return nil, ErrNotYetValid
	}
	if i.revoked != nil {
		revoked, err := i.revoked(ctx, c.Jti)
		if err != nil {
			return nil, fmt.Errorf("jwt: revocation check: %w", err)
		}
		if revoked {
			return nil, ErrRevoked
		}
	}
	return &c, nil
}

func intersects(want, got []string) bool {
	for _, w := range want {
		for _, g := range got {
			if w == g {
				return true
			}
		}
	}
	return false
}

// keyID names a secret without revealing it: the first 8 bytes of its
// SHA-256, base64url.
func keyID(secret []byte) string {
	sum := sha256.Sum256(append([]byte("passport-jwt-kid:"), secret...))
	return b64(sum[:8])
}

func sign(secret []byte, data string) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func b64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

var _ passport.TokenIssuer = (*Issuer)(nil)
