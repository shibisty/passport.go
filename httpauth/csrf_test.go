package httpauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"passport/ratelimit"
)

func TestGuards(t *testing.T) {
	a, sid, _ := setup(t)
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _ := FromContext(r.Context())
		w.Write([]byte(GuardFrom(r.Context()) + ":" + id.ProviderUserID))
	})
	call := func(h http.Handler, auth, cookieVal string) (int, string) {
		req := httptest.NewRequest("GET", "/", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		if cookieVal != "" {
			req.AddCookie(&http.Cookie{Name: CookieName, Value: cookieVal})
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	web, api := Web(a)(RequireAuth(echo)), API(a)(RequireAuth(echo))
	if code, body := call(web, "", sid); code != 200 || body != "web:session-user" {
		t.Fatalf("web+cookie: %d %s", code, body)
	}
	if code, _ := call(web, "Bearer good", ""); code != 401 {
		t.Fatalf("web+bearer: %d", code)
	}
	if code, body := call(api, "Bearer good", ""); code != 200 || body != "api:token-user" {
		t.Fatalf("api+bearer: %d %s", code, body)
	}
	if code, _ := call(api, "", sid); code != 401 {
		t.Fatalf("api+cookie: %d", code)
	}
	onlyAPI := Middleware(a)(RequireGuard(GuardAPI)(echo))
	if code, _ := call(onlyAPI, "", sid); code != 401 {
		t.Fatalf("RequireGuard(api) with a cookie: %d", code)
	}
	if code, _ := call(onlyAPI, "Bearer good", ""); code != 200 {
		t.Fatalf("RequireGuard(api) with a token: %d", code)
	}
}

func TestCSRF(t *testing.T) {
	ok := CSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(CSRFToken(r))) }))

	// GET hands out the cookie.
	rec := httptest.NewRecorder()
	ok.ServeHTTP(rec, httptest.NewRequest("GET", "/form", nil))
	var tok string
	for _, c := range rec.Result().Cookies() {
		if c.Name == CSRFCookieName {
			tok = c.Value
			if c.HttpOnly || !c.Secure {
				t.Fatalf("cookie flags: %+v", c)
			}
		}
	}
	if len(tok) < 32 || rec.Body.String() != tok {
		t.Fatalf("token %q, body %q", tok, rec.Body.String())
	}
	post := func(header, field string, withCookie bool, auth string) int {
		form := url.Values{}
		if field != "" {
			form.Set(CSRFField, field)
		}
		req := httptest.NewRequest("POST", "/save", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if header != "" {
			req.Header.Set(CSRFHeader, header)
		}
		if withCookie {
			req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: tok})
		}
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		ok.ServeHTTP(rec, req)
		return rec.Code
	}
	for name, c := range map[string]struct {
		code int
		got  int
	}{
		"header":            {200, post(tok, "", true, "")},
		"form field":        {200, post("", tok, true, "")},
		"missing":           {403, post("", "", true, "")},
		"wrong":             {403, post(strings.Repeat("x", 64), "", true, "")},
		"no cookie":         {403, post(tok, "", false, "")},
		"bearer is skipped": {200, post("", "", false, "Bearer abc")},
	} {
		if c.code != c.got {
			t.Errorf("%s: %d, want %d", name, c.got, c.code)
		}
	}
	if CSRFToken(httptest.NewRequest("GET", "/", nil)) != "" {
		t.Fatal("CSRFToken outside CSRF")
	}
}

func TestLimitLogin(t *testing.T) {
	now := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	l := ratelimit.New(2, time.Minute).WithClock(func() time.Time { return now })
	status := http.StatusUnauthorized
	h := LimitLogin(l, ClientIP, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))
	try := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/login", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	try()
	try()
	if rec := try(); rec.Code != 429 || rec.Header().Get("Retry-After") != "60" {
		t.Fatalf("third attempt: %d %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	now = now.Add(time.Minute)
	status = http.StatusOK
	if rec := try(); rec.Code != 200 {
		t.Fatalf("after the window: %d", rec.Code)
	}
	status = http.StatusUnauthorized // success reset the counter: two more tries
	try()
	if rec := try(); rec.Code != 401 {
		t.Fatalf("reset: %d", rec.Code)
	}
	if ClientIP(&http.Request{RemoteAddr: "unix"}) != "unix" {
		t.Fatal("ClientIP without a port")
	}
	// A handler that only writes a body is a success too.
	h2 := LimitLogin(l, func(*http.Request) string { return "k" }, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	rec := httptest.NewRecorder()
	h2.ServeHTTP(rec, httptest.NewRequest("POST", "/", nil))
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
}

func TestFormPostState(t *testing.T) {
	rec := httptest.NewRecorder()
	state, err := NewFormPostState(rec)
	if err != nil {
		t.Fatal(err)
	}
	c := rec.Result().Cookies()[0]
	if c.SameSite != http.SameSiteNoneMode || !c.Secure || !c.HttpOnly {
		t.Fatalf("cookie: %+v", c)
	}
	req := httptest.NewRequest("POST", "/cb", strings.NewReader(url.Values{"state": {state}, "code": {"x"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: StateCookieName, Value: state})
	if err := CheckState(httptest.NewRecorder(), req); err != nil {
		t.Fatalf("form_post state: %v", err)
	}
}
