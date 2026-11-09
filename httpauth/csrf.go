package httpauth

import (
	"context"
	"crypto/subtle"
	"net"
	"net/http"
	"strconv"
	"time"

	"passport/memorystore"
	"passport/ratelimit"
)

const (
	// CSRFCookieName holds the CSRF token (readable by JavaScript, which
	// copies it into the CSRFHeader).
	CSRFCookieName = "csrf_token"
	// CSRFHeader carries the token on fetch/XHR requests.
	CSRFHeader = "X-CSRF-Token"
	// CSRFField carries the token in HTML forms.
	CSRFField = "_csrf"
)

type csrfKey struct{}

// CSRF protects cookie-authenticated routes from cross-site requests with a
// double-submit token: every response makes sure the browser has a
// csrf_token cookie, and a POST, PUT, PATCH or DELETE must send the same
// value in the X-CSRF-Token header or the _csrf form field (403 otherwise).
// Requests with a Bearer token are not checked: browsers never add one by
// themselves. Put the token into forms with CSRFToken:
//
//	mux.Handle("/", httpauth.CSRF(httpauth.Web(a)(app)))
//	<input type="hidden" name="_csrf" value="{{ .CSRF }}">   // httpauth.CSRFToken(r)
func CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := ""
		if c, err := r.Cookie(CSRFCookieName); err == nil && len(c.Value) >= 32 {
			token = c.Value
		} else {
			id, err := memorystore.NewID()
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			token = id
			c := cookie(CSRFCookieName, token, 0)
			c.HttpOnly = false // JavaScript copies it into the header
			c.MaxAge = 0       // a browser-session cookie
			http.SetCookie(w, c)
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		default:
			if _, isBearer := bearer(r); !isBearer {
				got := r.Header.Get(CSRFHeader)
				if got == "" {
					got = r.PostFormValue(CSRFField)
				}
				if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
					http.Error(w, "invalid CSRF token", http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), csrfKey{}, token)))
	})
}

// CSRFToken returns the token of a request that passed through CSRF ("" otherwise).
func CSRFToken(r *http.Request) string {
	t, _ := r.Context().Value(csrfKey{}).(string)
	return t
}

// LimitLogin limits attempts of a login handler: key picks what is limited
// (ClientIP, or IP and email together); over the limit the response is 429
// with Retry-After. A response below 400 counts as a successful login and
// resets the key.
//
//	limiter := ratelimit.New(5, time.Minute)
//	mux.Handle("POST /login", httpauth.LimitLogin(limiter, func(r *http.Request) string {
//	    return httpauth.ClientIP(r) + "|" + r.PostFormValue("email")
//	}, loginHandler))
func LimitLogin(l ratelimit.Limiter, key func(*http.Request) string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k := key(r)
		ok, retry := l.Allow(k)
		if !ok {
			secs := int((retry + time.Second - 1) / time.Second)
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			http.Error(w, "too many login attempts", http.StatusTooManyRequests)
			return
		}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if rec.status < 400 {
			l.Reset(k)
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wrote {
		s.status, s.wrote = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.wrote = true
	return s.ResponseWriter.Write(b)
}

// ClientIP is the request's remote address without the port. It does not
// trust X-Forwarded-For: behind a proxy, take the address the proxy sets.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
