package jwt

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"passport"
)

const secret = "0123456789abcdef0123456789abcdef" // 32 bytes

var ctx = context.Background()

var ann = &passport.Identity{Provider: "google", ProviderUserID: "42", Email: "ann@x", EmailVerified: true, Name: "Ann", AvatarURL: "a.png"}

func mustNew(t *testing.T, opts ...Option) *Issuer {
	t.Helper()
	i, err := New(secret, "myapp", opts...)
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func TestRoundTrip(t *testing.T) {
	i := mustNew(t)
	tok, err := i.Issue(ctx, ann, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, err := i.Verify(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	want := *ann
	want.Raw = nil
	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("Verify = %+v, want %+v", *got, want)
	}
	// Format: three base64url parts, HS256/JWT header.
	h, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
	if string(h) != `{"alg":"HS256","typ":"JWT"}` {
		t.Fatalf("header = %s", h)
	}
}

func TestWeakSecretAndBadTTL(t *testing.T) {
	for _, s := range []string{"", "short", strings.Repeat("x", 31)} {
		if _, err := New(s, "app"); !errors.Is(err, ErrWeakSecret) {
			t.Errorf("New(%q): got %v", s, err)
		}
	}
	if _, err := mustNew(t).Issue(ctx, ann, 0); !errors.Is(err, ErrBadTTL) {
		t.Errorf("ttl 0: %v", err)
	}
}

// forge assembles a token with an arbitrary header, payload and signature.
func forge(header, claims, sig string) string {
	return b64([]byte(header)) + "." + b64([]byte(claims)) + "." + sig
}

func TestRejects(t *testing.T) {
	i := mustNew(t)
	good, _ := i.Issue(ctx, ann, time.Hour)
	parts := strings.Split(good, ".")
	now := time.Now().Unix()
	claims := `{"iss":"myapp","sub":"1","provider":"local","iat":1,"exp":` + itoa(now+3600) + `}`
	signed := func(header, claims string) string {
		in := b64([]byte(header)) + "." + b64([]byte(claims))
		return in + "." + b64(sign([]byte(secret), in))
	}

	cases := []struct {
		name  string
		token string
		want  error
	}{
		{"two parts", "a.b", ErrMalformedToken},
		{"bad header base64", "!!." + parts[1] + "." + parts[2], ErrMalformedToken},
		{"header not json", b64([]byte("x")) + "." + parts[1] + "." + parts[2], ErrMalformedToken},
		{"alg none", forge(`{"alg":"none"}`, claims, ""), ErrBadAlgorithm},
		{"alg RS256", forge(`{"alg":"RS256"}`, claims, parts[2]), ErrBadAlgorithm},
		{"bad signature base64", parts[0] + "." + parts[1] + ".!!", ErrMalformedToken},
		{"tampered claims", parts[0] + "." + b64([]byte(strings.Replace(claims, `"sub":"1"`, `"sub":"2"`, 1))) + "." + parts[2], ErrBadSignature},
		{"other secret", func() string {
			o, _ := New(strings.Repeat("z", 32), "myapp")
			tok, _ := o.Issue(ctx, ann, time.Hour)
			return tok
		}(), ErrBadSignature},
		{"claims not json", signed(`{"alg":"HS256"}`, "nope"), ErrMalformedToken},
		{"other issuer", signed(`{"alg":"HS256"}`, strings.Replace(claims, "myapp", "evil", 1)), ErrBadIssuer},
		{"expired", signed(`{"alg":"HS256"}`, `{"iss":"myapp","sub":"1","exp":`+itoa(now-10)+`}`), ErrExpired},
		{"no exp", signed(`{"alg":"HS256"}`, `{"iss":"myapp","sub":"1"}`), ErrExpired},
		{"not yet valid", signed(`{"alg":"HS256"}`, `{"iss":"myapp","sub":"1","exp":`+itoa(now+100)+`,"nbf":`+itoa(now+50)+`}`), ErrNotYetValid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := i.Verify(ctx, tc.token); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	// The signature is valid, but the claims are not base64.
	in := parts[0] + ".!!"
	if _, err := i.Verify(ctx, in+"."+b64(sign([]byte(secret), in))); !errors.Is(err, ErrMalformedToken) {
		t.Fatalf("claims base64: %v", err)
	}
}

func TestClockAndLeeway(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	now := t0
	clock := func() time.Time { return now }
	i := mustNew(t, WithClock(clock))
	tok, _ := i.Issue(ctx, ann, time.Minute)

	now = t0.Add(59 * time.Second)
	if _, err := i.Verify(ctx, tok); err != nil {
		t.Fatalf("before expiry: %v", err)
	}
	now = t0.Add(61 * time.Second)
	if _, err := i.Verify(ctx, tok); !errors.Is(err, ErrExpired) {
		t.Fatalf("after expiry: %v", err)
	}
	lenient := mustNew(t, WithClock(clock), WithLeeway(30*time.Second))
	if _, err := lenient.Verify(ctx, tok); err != nil {
		t.Fatalf("within leeway: %v", err)
	}
	// An empty issuer in Issuer is not checked.
	anyIss, _ := New(secret, "", WithClock(func() time.Time { return t0 }))
	if _, err := anyIss.Verify(ctx, tok); err != nil {
		t.Fatalf("empty issuer accepts any iss: %v", err)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
