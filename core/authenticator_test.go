package passport_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"passport"
)

var ctx = context.Background()

type credStrategy struct{ name string }

func (s credStrategy) Name() string { return s.name }
func (s credStrategy) Authenticate(_ context.Context, c map[string]string) (*passport.Identity, error) {
	if c["password"] != "ok" {
		return nil, passport.ErrInvalidCredentials
	}
	return &passport.Identity{Provider: s.name, ProviderUserID: c["user"]}, nil
}

type redirectStrategy struct{}

func (redirectStrategy) Name() string { return "oauth" }
func (redirectStrategy) AuthCodeURL(state string) string {
	return "https://provider/auth?state=" + state
}
func (redirectStrategy) Callback(_ context.Context, p map[string]string) (*passport.Identity, error) {
	return &passport.Identity{Provider: "oauth", ProviderUserID: p["code"]}, nil
}

type fakeSessions struct {
	mu   sync.Mutex
	data map[string]*passport.Identity
}

func (f *fakeSessions) Create(_ context.Context, id *passport.Identity, _ time.Duration) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data["s1"] = id
	return "s1", nil
}
func (f *fakeSessions) Get(_ context.Context, sid string) (*passport.Identity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id, ok := f.data[sid]; ok {
		return id, nil
	}
	return nil, passport.ErrSessionNotFound
}
func (f *fakeSessions) Destroy(_ context.Context, sid string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.data, sid)
	return nil
}

type fakeTokens struct{}

func (fakeTokens) Issue(_ context.Context, id *passport.Identity, _ time.Duration) (string, error) {
	return "tok-" + id.ProviderUserID, nil
}
func (fakeTokens) Verify(_ context.Context, tok string) (*passport.Identity, error) {
	if tok != "tok-7" {
		return nil, errors.New("bad token")
	}
	return &passport.Identity{ProviderUserID: "7"}, nil
}

func TestCredentialAndRedirect(t *testing.T) {
	a := passport.New().Use(credStrategy{"local"}).Use(redirectStrategy{})

	id, err := a.Credential(ctx, "local", map[string]string{"user": "7", "password": "ok"})
	if err != nil || id.ProviderUserID != "7" {
		t.Fatalf("Credential = %+v, %v", id, err)
	}
	if _, err := a.Credential(ctx, "local", map[string]string{"password": "no"}); !errors.Is(err, passport.ErrInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}

	url, err := a.RedirectURL("oauth", "st")
	if err != nil || url != "https://provider/auth?state=st" {
		t.Fatalf("RedirectURL = %q, %v", url, err)
	}
	id, err = a.Callback(ctx, "oauth", map[string]string{"code": "c1"})
	if err != nil || id.ProviderUserID != "c1" {
		t.Fatalf("Callback = %+v, %v", id, err)
	}

	cases := []struct {
		name string
		call func() error
		want error
	}{
		{"unknown credential", func() error { _, e := a.Credential(ctx, "nope", nil); return e }, passport.ErrStrategyNotFound},
		{"unknown redirect", func() error { _, e := a.RedirectURL("nope", ""); return e }, passport.ErrStrategyNotFound},
		{"credential on redirect strategy", func() error { _, e := a.Credential(ctx, "oauth", nil); return e }, passport.ErrUnsupportedStrategyType},
		{"redirect on credential strategy", func() error { _, e := a.RedirectURL("local", ""); return e }, passport.ErrUnsupportedStrategyType},
		{"callback on credential strategy", func() error { _, e := a.Callback(ctx, "local", nil); return e }, passport.ErrUnsupportedStrategyType},
	}
	for _, tc := range cases {
		if err := tc.call(); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestSessionsAndTokens(t *testing.T) {
	a := passport.New()
	id := &passport.Identity{ProviderUserID: "7"}

	if _, err := a.StartSession(ctx, id, time.Hour); !errors.Is(err, passport.ErrNoSessionStore) {
		t.Errorf("StartSession without store: %v", err)
	}
	if _, err := a.VerifySession(ctx, "x"); !errors.Is(err, passport.ErrNoSessionStore) {
		t.Errorf("VerifySession without store: %v", err)
	}
	if err := a.EndSession(ctx, "x"); !errors.Is(err, passport.ErrNoSessionStore) {
		t.Errorf("EndSession without store: %v", err)
	}
	if _, err := a.IssueToken(ctx, id, time.Hour); !errors.Is(err, passport.ErrNoTokenIssuer) {
		t.Errorf("IssueToken without issuer: %v", err)
	}
	if _, err := a.VerifyToken(ctx, "x"); !errors.Is(err, passport.ErrNoTokenIssuer) {
		t.Errorf("VerifyToken without issuer: %v", err)
	}

	a.UseSessionStore(&fakeSessions{data: map[string]*passport.Identity{}}).UseTokenIssuer(fakeTokens{})
	sid, err := a.StartSession(ctx, id, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := a.VerifySession(ctx, sid); err != nil || got.ProviderUserID != "7" {
		t.Fatalf("VerifySession = %+v, %v", got, err)
	}
	if err := a.EndSession(ctx, sid); err != nil {
		t.Fatal(err)
	}
	if _, err := a.VerifySession(ctx, sid); !errors.Is(err, passport.ErrSessionNotFound) {
		t.Fatalf("after EndSession: %v", err)
	}
	tok, err := a.IssueToken(ctx, id, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := a.VerifyToken(ctx, tok); err != nil || got.ProviderUserID != "7" {
		t.Fatalf("VerifyToken = %+v, %v", got, err)
	}
}

// Registration and login concurrently from different goroutines (run with -race).
func TestConcurrentConfiguration(t *testing.T) {
	a := passport.New()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); a.Use(credStrategy{"local"}).UseTokenIssuer(fakeTokens{}) }()
		go func() {
			defer wg.Done()
			_, _ = a.Credential(ctx, "local", map[string]string{"password": "ok"})
			_, _ = a.VerifyToken(ctx, "tok-7")
		}()
	}
	wg.Wait()
}
