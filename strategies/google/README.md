# passport-google

Google login for [passport](https://github.com/shibisty/passport.go). Built on
[`passport-oauth2`](https://github.com/shibisty/passport.go-oauth2-strategy).

## Installation

```bash
gtr add github:shibisty/passport.go github:shibisty/passport.go-google-strategy
```

`passport` is a peer dependency (`^0.1`): the application adds it, and every strategy
plugs into the same `Authenticator`. `passport-oauth2` comes along as a dependency.

## Usage

Import as `google "passport-google"` (Go package `google`), next to `"passport"`.

```go
a.Use(google.New(clientID, clientSecret, "https://app.example/auth/google/callback"))
```

Get the credentials in the [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
(OAuth client ID, type "Web application"); the redirect URL must match exactly.

- Default scopes: `openid email profile`; custom ones via `google.WithScopes(...)`.
- `Identity`: `ProviderUserID` = `sub`, `Email`, `EmailVerified` (`email_verified`),
  `Name`, `AvatarURL` (`picture`).
- `google.WithAuthParam("prompt", "select_account")` — extra login parameters.
- `google.WithHTTPClient`, `google.WithEndpoints` (for tests with `oauth2test`).

Login handlers and CSRF protection work as described in the `passport-oauth2` README.

## Tests

In a checkout, run `gtr install` once, then `gtr run test`.

## License

MIT
