# passport-oauth2

A generic OAuth2 strategy (Authorization Code flow) for
[passport](https://github.com/shibisty/passport.go). Standard library only.
`passport-google` and `passport-facebook` are built on it; any other provider is
just a `Config` and a profile-mapping function:

## Installation

```bash
gtr add github:shibisty/passport.go github:shibisty/passport.go-oauth2-strategy
```

`passport` is a peer dependency (`^0.1`): the application adds it, and every strategy
plugs into the same `Authenticator`.

## Usage

Import as `oauth2 "passport-oauth2"` (Go package `oauth2`), next to `"passport"`.

```go
github := oauth2.New("github", oauth2.Config{
	ClientID: id, ClientSecret: secret,
	RedirectURL: "https://app.example/auth/github/callback",
	AuthURL:     "https://github.com/login/oauth/authorize",
	TokenURL:    "https://github.com/login/oauth/access_token",
	UserInfoURL: "https://api.github.com/user",
	Scopes:      []string{"read:user", "user:email"},
}, func(p map[string]any) (*passport.Identity, error) {
	return &passport.Identity{ProviderUserID: oauth2.String(p, "id"), Name: oauth2.String(p, "name")}, nil
})
a.Use(github)
```

Login in handlers (with CSRF protection from `passport/httpauth`):

```go
// GET /auth/github
state, _ := httpauth.NewState(w)
url, _ := a.RedirectURL("github", state)
http.Redirect(w, r, url, http.StatusFound)

// GET /auth/github/callback
if err := httpauth.CheckState(w, r); err != nil { /* 400 */ }
identity, err := a.Callback(ctx, "github", map[string]string{"code": r.URL.Query().Get("code"), "error": r.URL.Query().Get("error")})
```

- Provider request timeout is 15 s (`DefaultTimeout`) unless you set your own `HTTPClient`.
- A response larger than 1 MB is an error; the error message includes at most 512 bytes of the response body.
- Errors: `ErrAccessDenied` (the user declined), `ErrMissingCode`, `ErrNoUserID`.
- `oauth2.String` understands numeric ids (GitHub); `oauth2.Bool` understands `"true"` as a string.

## Testing strategies: `oauth2test`

A fake provider built on `httptest`:

```go
p := oauth2test.NewProvider(t, map[string]any{"id": "42", "email": "a@x"})
s := oauth2.New("acme", oauth2.Config{
	ClientID: p.ClientID, ClientSecret: p.ClientSecret,
	AuthURL: p.AuthURL(), TokenURL: p.TokenURL(), UserInfoURL: p.UserInfoURL(),
}, mapper)
identity, err := s.Callback(ctx, map[string]string{"code": p.Code})
```

`TokenStatus`, `TokenBody`, `UserInfoStatus`, `UserInfoBody` override responses for
testing errors; `Requests()` returns the received requests.

## Tests

In a checkout, run `gtr install` once, then `gtr run test`.

## License

MIT
