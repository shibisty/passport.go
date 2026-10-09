# passport.go — local layout of the family

Not a repository: each subdirectory below is a separate repository (ADR-0006).

| Directory | Repository | gtr package |
|---|---|---|
| `core` | `shibisty/passport.go` | `passport` |
| `strategies/local` | `shibisty/passport.go-local-strategy` | `passport-local` |
| `strategies/oauth2` | `shibisty/passport.go-oauth2-strategy` | `passport-oauth2` |
| `strategies/google` | `shibisty/passport.go-google-strategy` | `passport-google` |
| `strategies/facebook` | `shibisty/passport.go-facebook-strategy` | `passport-facebook` |
| `sessions/redis` | `shibisty/passport.go-redis-session` | `passport-session-redis` |
| `sessions/file` | `shibisty/passport.go-file-session` | `passport-session-file` |
| `example` | — | example application |

`gtr.json` here (not committed) makes the folder a gtr workspace (ADR-0009): the packages
are used in place, while each package's own `gtr.json` keeps its real sources for its CI.
`passport-session-redis` and the example need orm: the workspace takes `orm`, `orm-redis`
and `orm-postgres` from the sibling folder `orm.go` (`file:` dependencies of the workspace
root), so `orm.go` must sit alongside.

```bash
gtr install          # one gtr.lock and gtr_modules/ here
gtr run -r test      # every package's tests
cd example && gtr run test
```
