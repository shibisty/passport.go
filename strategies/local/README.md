# passport-local

Email and password login for [passport](https://github.com/shibisty/passport.go),
the equivalent of passport-local.

## Installation

```bash
gtr add github:shibisty/passport.go github:shibisty/passport.go-local-strategy
```

`passport` is a peer dependency (`^0.1`): the application adds it, and every strategy
plugs into the same `Authenticator`.

## Usage

Import as `local "passport-local"` (Go package `local`), next to `"passport"`.

```go
a.Use(local.New(func(ctx context.Context, email, password string) (*passport.Identity, error) {
	u, err := users.FindByEmail(ctx, email)
	if err != nil {
		return nil, err // a DB error is not a "wrong password"
	}
	hash := dummyHash // so the response time does not reveal whether the email exists
	if u != nil {
		hash = u.PasswordHash
	}
	if ok, _ := passwordhash.Verify(password, hash); u == nil || !ok {
		return nil, local.ErrInvalidCredentials
	}
	return &passport.Identity{ProviderUserID: strconv.FormatInt(u.ID, 10), Email: u.Email}, nil
}))

identity, err := a.Credential(ctx, "local", map[string]string{"email": e, "password": p})
```

- The email is trimmed; an empty email or password yields `ErrInvalidCredentials` without
  calling your function.
- `Provider` is set to `"local"` if you did not set it.
- Custom field names: `local.New(verify, local.WithFields("login", "pass"))`.

`local.ErrInvalidCredentials` is `passport.ErrInvalidCredentials`.

## Tests

In a checkout, run `gtr install` once, then `gtr run test`.

## License

MIT
