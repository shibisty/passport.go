# passport-facebook

Facebook login for [passport](https://github.com/shibisty/passport.go). Built on
[`passport-oauth2`](https://github.com/shibisty/passport.go-oauth2-strategy).

## Installation

```bash
gtr add github:shibisty/passport.go github:shibisty/passport.go-facebook-strategy
```

`passport` is a peer dependency (`^0.1`): the application adds it, and every strategy
plugs into the same `Authenticator`. `passport-oauth2` comes along as a dependency.

## Usage

Import as `facebook "passport-facebook"` (Go package `facebook`), next to `"passport"`.

```go
a.Use(facebook.New(appID, appSecret, "https://app.example/auth/facebook/callback"))
```

- Default Graph API version: `v26.0` (`facebook.DefaultAPIVersion`); Meta supports each version
  for about two years; to change it, use `facebook.WithAPIVersion("v27.0")`.
- Default scopes: `email public_profile`.
- `Identity.EmailVerified` is always `false`: Facebook does not report whether the email is verified,
  so linking accounts by it is unsafe.
- `facebook.WithHTTPClient`, `facebook.WithEndpoints` (for tests with `oauth2test`).

## Tests

In a checkout, run `gtr install` once, then `gtr run test`.

## License

MIT
