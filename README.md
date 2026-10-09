# passport

Authentication for Go in the style of [passport.js](https://www.passportjs.org/): a single
`Authenticator` and independent strategy packages. The core uses only the standard library.

[![Patreon](https://c5.patreon.com/external/logo/become_a_patron_button.png)](https://www.patreon.com/cw/shibisty)

| Package | What it is |
|---|---|
| `passport` (this repository) | `Authenticator`, interfaces, subpackages `jwt`, `passwordhash`, `memorystore`, `httpauth`, `sessionstoretest` |
| [`passport-local`](https://github.com/shibisty/passport.go-local-strategy) | Email and password login |
| [`passport-oauth2`](https://github.com/shibisty/passport.go-oauth2-strategy) | Any OAuth2 provider (Authorization Code) + a fake provider for tests |
| [`passport-google`](https://github.com/shibisty/passport.go-google-strategy) | Google |
| [`passport-facebook`](https://github.com/shibisty/passport.go-facebook-strategy) | Facebook |
| [`passport-session-redis`](https://github.com/shibisty/passport.go-redis-session) | Sessions in Redis (via `orm.KeyValueStore`) |
| [`passport-session-file`](https://github.com/shibisty/passport.go-file-session) | Sessions as files in a directory (no database) |

Requires Go 1.22+.

## Installation

With [gtr](https://github.com/shibisty/gtr) (until the gtr registry, by repository):

```bash
gtr add github:shibisty/passport.go github:shibisty/passport.go-local-strategy
```

Then `import "passport"`; strategies have `passport` as a peer dependency.

## How it works

As in passport.js, two questions are kept separate:

1. **"Who are you?"** — the login strategy: `CredentialStrategy` (username and password) or
   `RedirectStrategy` (OAuth2). The result is always the same: `*passport.Identity`.
2. **"Are you still you?"** — on subsequent requests: `SessionStore` (cookie session) and/or
   `TokenIssuer` (JWT), regardless of how the user logged in.

```go
tokens, err := jwt.New(os.Getenv("JWT_SECRET"), "myapp") // secret ≥ 32 bytes
if err != nil {
	log.Fatal(err)
}
a := passport.New().
	UseSessionStore(memorystore.New()). // in production: passport-session-file or passport-session-redis
	UseTokenIssuer(tokens).
	Use(local.New(verifyPassword)).
	Use(google.New(clientID, clientSecret, "https://app.example/auth/google/callback"))

mux.Handle("GET /me", httpauth.RequireAuth(meHandler))
http.ListenAndServe(":8080", httpauth.Middleware(a)(mux))
```

Full example — password login, Google/Facebook, logout, JWT, with a test of the whole flow:
[`passport.go/example`](../example).

## Subpackages

### `jwt` — HS256 tokens

- `jwt.New(secret, issuer, opts...)` returns an error if the secret is shorter than 32 bytes.
- `Verify` accepts only `alg: HS256` (no `none`), and checks the signature,
  `iss`, `exp` and `nbf`. Clock skew tolerance: `jwt.WithLeeway(d)`.

### `passwordhash` — PBKDF2-HMAC-SHA256

- `Hash(password)` — 600,000 iterations (OWASP recommendation), 16-byte salt.
  Format: `pbkdf2-sha256$<iterations>$<salt>$<key>` (unpadded base64).
- `Verify(password, hash)` — constant-time comparison; a corrupted string yields
  `ErrInvalidHash`.
- `NeedsRehash(hash)` — `true` if the hash was created with outdated parameters: recompute
  it after a successful login.

If the user is not found, still call `Verify` against a precomputed
dummy hash — otherwise the response time reveals whether the email is registered (the
example does this).

### `httpauth` — net/http

- `Middleware(a)` identifies the user by `Authorization: Bearer …`, then by the
  `session_id` cookie; `RequireAuth` responds with 401, `FromContext` returns the `Identity`.
- `SetSessionCookie` / `ClearSessionCookie` — cookie `HttpOnly`, `Secure`, `SameSite=Lax`.
- `NewState(w)` / `CheckState(w, r)` — CSRF protection for OAuth2 login: a random
  single-use `state` in a cookie for 10 minutes. Call `CheckState` before `a.Callback`.

### `memorystore` — in-memory sessions

For development and tests: sessions are lost on restart and are not visible to other
application instances. To keep them across restarts on one server, use
`passport-session-file`; for several servers, `passport-session-redis`.

### `sessionstoretest` — tests for your own session store

```go
func TestMyStore(t *testing.T) {
	sessionstoretest.Run(t, mystore.New(...), time.Second)
}
```

Tests creation, reading, deletion, expiry, ID uniqueness and
concurrent access.

## Security

- Link accounts by email only when `Identity.EmailVerified == true`.
- `Identity.Raw` (the raw provider profile) is not serialized to JSON and never ends up
  in sessions or tokens.
- `SessionStore.Get` returns `ErrSessionNotFound` only when the session does not exist;
  store errors (Redis unavailable) are returned as is, so they are not mistaken for "not logged in".

## Development

In a checkout, run `gtr install` once (it generates `go.mod`), then:

```bash
gtr run test -- -race
```

Local layout of the family: `passport.go/{core,strategies/*,sessions/*,example}`,
a gtr workspace (ADR-0006, ADR-0009).

[![Patreon](https://c5.patreon.com/external/logo/become_a_patron_button.png)](https://www.patreon.com/cw/shibisty)

If this project helps you, consider supporting its development on Patreon ❤️
