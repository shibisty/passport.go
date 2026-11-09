# passport

Authentication for Go in the style of [passport.js](https://www.passportjs.org/): a single
`Authenticator` and independent strategy packages. The core uses only the standard library.

[![Patreon](https://c5.patreon.com/external/logo/become_a_patron_button.png)](https://www.patreon.com/cw/shibisty)

| Package | What it is |
|---|---|
| `passport` (this repository) | `Authenticator`, interfaces, subpackages `jwt`, `refresh`, `passwordhash`, `ratelimit`, `memorystore`, `httpauth`, `sessionstoretest` |
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
- `Verify` checks, in order: size (≤ 8 KiB); header — `alg` exactly `HS256` (`none`,
  `RS256`, `hs256` are rejected), `typ` `JWT` if present, no `crit`, a known `kid`; the
  HMAC signature in constant time; then `sub` (required), `iss`, `aud`, `exp` (required),
  `nbf` and revocation. The key is never taken from the token (`jku`, `jwk`, `x5u` are
  ignored).
- Options: `WithLeeway(d)` (clock skew), `WithAudience("api")` (written to `aud`, required
  on verify), `WithPreviousSecrets(old...)` (key rotation: tokens name their key in
  `kid`, derived from the secret), `WithRevocation(func(ctx, jti) (bool, error))` (every
  token has a random `jti`; `TokenID(ctx, token)` returns it and the expiry for a logout
  list).

```go
issuer, err := jwt.New(os.Getenv("JWT_SECRET"), "myapp",
    jwt.WithAudience("api"),
    jwt.WithPreviousSecrets(os.Getenv("JWT_SECRET_OLD")),
    jwt.WithRevocation(func(ctx context.Context, jti string) (bool, error) {
        return redis.Exists(ctx, "revoked:"+jti) // set on logout until the token expires
    }))
```

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
- Guards, as in Laravel: `Web(a)` accepts only the session cookie, `API(a)` only a Bearer
  token (so a browser's cookie never authenticates an API call); `GuardFrom(ctx)` says
  which one did (`GuardWeb`, `GuardAPI`), `RequireGuard(GuardAPI)` refuses the other.
- `CSRF(next)` — double-submit token for cookie-authenticated routes: every response
  makes sure there is a `csrf_token` cookie, and `POST`/`PUT`/`PATCH`/`DELETE` must send
  it back in `X-CSRF-Token` or the `_csrf` form field (403 otherwise). Bearer requests are
  not checked. `CSRFToken(r)` gives the value for a form.
- `LimitLogin(limiter, key, handler)` — 429 with `Retry-After` after too many attempts per
  key (`ClientIP(r)`, or IP and email); a successful response (< 400) resets the key.
- `SetSessionCookie` / `ClearSessionCookie` — cookie `HttpOnly`, `Secure`, `SameSite=Lax`.
- `NewState(w)` / `CheckState(w, r)` — CSRF protection for OAuth2 login: a random
  single-use `state` in a cookie for 10 minutes. Call `CheckState` before `a.Callback`.

### `refresh` — rotating refresh tokens

```go
refresher := refresh.New(refresh.NewMemoryStore(), 30*24*time.Hour)
pair, err := refresher.Issue(ctx, issuer, identity, 15*time.Minute) // access JWT + refresh token
pair, err = refresher.Rotate(ctx, issuer, pair.Refresh, 15*time.Minute)
err = refresher.Revoke(ctx, pair.Refresh) // logout
```

- A refresh token is 32 random bytes; the store keeps only its SHA-256.
- Each `Rotate` spends the token and issues the next one of the same login (family);
  presenting a spent token again revokes the whole family (`ErrReused`): a stolen token
  is useless after the user's next refresh, and the thief's use logs both out.
- `Store` is four methods (`Save`, `Get`, atomic `Spend`, `RevokeFamily`); `MemoryStore` is
  for tests and one process.

### `ratelimit` — login attempts

`ratelimit.New(5, time.Minute)` allows 5 attempts a minute per key in a sliding window,
in memory (`Allow(key)`, `Reset(key)`); implement `ratelimit.Limiter` on Redis for several
instances. `httpauth.LimitLogin` uses it.

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
