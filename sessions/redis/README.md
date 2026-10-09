# passport-session-redis

`passport.SessionStore` on top of `orm.KeyValueStore`: sessions in Redis, shared by all
application instances. It depends on the [orm](https://github.com/shibisty/orm.go) core
rather than on a specific driver, so any orm key-value store will do; usually that is
[`orm-redis`](https://github.com/shibisty/orm.go-redis-driver).

## Installation

```bash
gtr add github:shibisty/passport.go github:shibisty/orm.go \
        github:shibisty/orm.go-redis-driver github:shibisty/passport.go-redis-session
```

`passport` and `orm` are peer dependencies (`^0.1`): the application adds them, along with
the orm driver it uses for the key-value store.

## Usage

Import as `redisstore "passport-session-redis"` (Go package `redisstore`).

```go
conn, err := orm.New(ctx, redis.Driver("redis://localhost:6379/0"))
if err != nil {
	log.Fatal(err)
}
kv, ok := conn.(orm.KeyValueStore)
if !ok {
	log.Fatal("not a key-value store")
}
a := passport.New().UseSessionStore(redisstore.New(kv).WithPrefix("myapp:session:"))
```

- Key: `session:<id>` (prefix configurable via `WithPrefix`); the id is 32 random bytes.
- The lifetime is rounded up to whole seconds (minimum 1 s); a TTL ≤ 0 is an error.
- All `Identity` fields are stored except `Raw` (the provider profile and tokens are not stored).
- No session: `passport.ErrSessionNotFound`; Redis unavailable: the error is returned as is.

## Tests

In a checkout, run `gtr install` once (it also installs orm and orm-redis for the tests), then:

```bash
gtr run test                                                    # without Redis
ORM_TEST_REDIS_DSN=redis://127.0.0.1:6379/15 gtr run test:integration
```

Both runs execute the shared `passport/sessionstoretest` suite.

## License

MIT
