# Changelog

## Unreleased

### Added
- `filestore.New(dir)`: a `passport.SessionStore` keeping one file per session
  (`<id>.session`, mode 0600, in a directory with mode 0700), written atomically; expired
  sessions are removed when read, swept every 256 sessions and by `Cleanup`.
- Tests: the shared `sessionstoretest` suite, forged ids, file system errors, sweeping.
