# passport-session-file

`passport.SessionStore` on the file system: one file per session in a directory. No
database, and sessions survive a restart. The Go package is `filestore`; standard library
only.

| Store | When |
|---|---|
| `passport/memorystore` | tests, one process, sessions may be lost on restart |
| `passport-session-file` (this package) | one server (several processes share the directory), no database |
| [`passport-session-redis`](https://github.com/shibisty/passport.go-redis-session) | several servers |

## Installation

```bash
gtr add github:shibisty/passport.go github:shibisty/passport.go-file-session
```

`passport` is a peer dependency (`^0.1`): the application adds it.

## Usage

Import as `filestore "passport-session-file"` (Go package `filestore`).

```go
sessions, err := filestore.New("var/sessions") // created with mode 0700 if missing
if err != nil {
	log.Fatal(err)
}
a := passport.New().UseSessionStore(sessions)
```

- A session is `<dir>/<id>.session` (JSON: the `Identity` without `Raw`, and the expiry),
  mode 0600. The id is 32 random bytes in hex; any other id (from a forged cookie) is
  `passport.ErrSessionNotFound` and never names another file.
- A file is written under a temporary name and renamed, so readers see a complete session
  or none, also from other processes using the same directory.
- An expired session is removed when read. `Create` sweeps expired sessions every 256
  sessions; with few logins call `sessions.Cleanup(ctx)` on a timer as well.
- No session: `passport.ErrSessionNotFound`; a file system error (no permission, a broken
  disk) or a corrupted file is returned as an error, not as "not logged in".
- A TTL ≤ 0 is an error.

Keep the directory out of the web root and out of version control.

## Tests

In a checkout, run `gtr install` once, then `gtr run test`. The shared
`passport/sessionstoretest` suite runs against a temporary directory.

## License

MIT
