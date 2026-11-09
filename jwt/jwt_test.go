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
	if !strings.HasPrefix(string(h), `{"alg":"HS256","typ":"JWT","kid":"`) {
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
		}(), ErrUnknownKey},
		{"claims not json", signed(`{"alg":"HS256"}`, "nope"), ErrMalformedToken},
		{"other issuer", signed(`{"alg":"HS256"}`, strings.Replace(claims, "myapp", "evil", 1)), ErrBadIssuer},
		{"expired", signed(`{"alg":"HS256"}`, `{"iss":"myapp","sub":"1","exp":`+itoa(now-10)+`}`), ErrExpired},
		{"no exp", signed(`{"alg":"HS256"}`, `{"iss":"myapp","sub":"1"}`), ErrExpired},
		{"typ refresh", signed(`{"alg":"HS256","typ":"refresh+jwt"}`, claims), ErrBadType},
		{"crit", signed(`{"alg":"HS256","crit":["exp"]}`, claims), ErrMalformedToken},
		{"no sub", signed(`{"alg":"HS256"}`, `{"iss":"myapp","exp":`+itoa(now+100)+`}`), ErrMissingSubject},
		{"too long", strings.Repeat("a", MaxTokenLength+1), ErrMalformedToken},
		{"current kid, other key", func() string {
			in := b64([]byte(`{"alg":"HS256","kid":"`+keyID([]byte(secret))+`"}`)) + "." + b64([]byte(claims))
			return in + "." + b64(sign([]byte(strings.Repeat("q", 32)), in))
		}(), ErrBadSignature},
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

func TestAudience(t *testing.T) {
	api := mustNew(t, WithAudience("api"))
	tok, _ := api.Issue(ctx, ann, time.Hour)
	if _, err := api.Verify(ctx, tok); err != nil {
		t.Fatal(err)
	}
	admin := mustNew(t, WithAudience("admin", "ops"))
	if _, err := admin.Verify(ctx, tok); !errors.Is(err, ErrBadAudience) {
		t.Fatalf("other audience: %v", err)
	}
	plain, _ := mustNew(t).Issue(ctx, ann, time.Hour) // no aud at all
	if _, err := api.Verify(ctx, plain); !errors.Is(err, ErrBadAudience) {
		t.Fatalf("missing aud: %v", err)
	}
	both, _ := admin.Issue(ctx, ann, time.Hour) // aud as a list
	if _, err := mustNew(t, WithAudience("ops")).Verify(ctx, both); err != nil {
		t.Fatalf("aud list: %v", err)
	}
	var a audience
	if err := a.UnmarshalJSON([]byte(`7`)); err == nil {
		t.Fatal("aud of a number accepted")
	}
}

func TestRotation(t *testing.T) {
	old := mustNew(t)
	tok, _ := old.Issue(ctx, ann, time.Hour)
	newSecret := strings.Repeat("n", 32)
	rotated, err := New(newSecret, "myapp", WithPreviousSecrets(secret))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotated.Verify(ctx, tok); err != nil {
		t.Fatalf("token of the previous secret: %v", err)
	}
	fresh, _ := rotated.Issue(ctx, ann, time.Hour)
	if _, err := old.Verify(ctx, fresh); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("new token on the old issuer: %v", err)
	}
	only, _ := New(newSecret, "myapp")
	if _, err := only.Verify(ctx, tok); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("previous secret dropped: %v", err)
	}
	if _, err := New(newSecret, "myapp", WithPreviousSecrets("short")); !errors.Is(err, ErrWeakSecret) {
		t.Fatalf("weak previous secret: %v", err)
	}
	if _, err := New(newSecret, "myapp", WithLeeway(-time.Second)); err == nil {
		t.Fatal("negative leeway")
	}
}

func TestRevocation(t *testing.T) {
	revoked := map[string]bool{}
	var fail error
	i := mustNew(t, WithRevocation(func(_ context.Context, jti string) (bool, error) { return revoked[jti], fail }))
	tok, _ := i.Issue(ctx, ann, time.Hour)
	other, _ := i.Issue(ctx, ann, time.Hour)
	jti, exp, err := i.TokenID(ctx, tok)
	if err != nil || jti == "" || time.Until(exp) < 59*time.Minute {
		t.Fatalf("TokenID: %q %v %v", jti, exp, err)
	}
	if j2, _, _ := i.TokenID(ctx, other); j2 == jti {
		t.Fatal("two tokens share a jti")
	}
	revoked[jti] = true
	if _, err := i.Verify(ctx, tok); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked: %v", err)
	}
	if _, err := i.Verify(ctx, other); err != nil {
		t.Fatalf("other token: %v", err)
	}
	fail = errors.New("store down")
	if _, err := i.Verify(ctx, other); err == nil || !strings.Contains(err.Error(), "store down") {
		t.Fatalf("revocation error: %v", err)
	}
	if _, _, err := i.TokenID(ctx, "x"); err == nil {
		t.Fatal("TokenID of garbage")
	}
	if _, err := i.Issue(ctx, &passport.Identity{Provider: "local"}, time.Hour); !errors.Is(err, ErrMissingSubject) {
		t.Fatalf("Issue without a subject: %v", err)
	}
	if _, err := i.Issue(ctx, nil, time.Hour); !errors.Is(err, ErrMissingSubject) {
		t.Fatalf("Issue(nil): %v", err)
	}
}
