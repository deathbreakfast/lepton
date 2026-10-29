# Changelog

All notable changes to `lepton-identity` are recorded here.

## [Unreleased]

### Changed

- Service user handles are now unique at the storage layer: `handle_key` carries
  a `unique: true` constraint and the `service_user_account` schema moves to
  version `0.2.0` so the boot sync picks the constraint up. A deleted service
  user's handle frees for reuse once its row is purged; while the deletion is
  still queued, the handle stays taken.
- Creating a service user serializes its quota count, handle check, and insert,
  so two requests racing for the same owner can no longer both slip past the
  per-owner limit or claim the same handle. The unique constraint backs this up
  across processes.
- A service user gate that cannot reach a decision is logged at `warn`, and a
  missing storage backend is now its own `Misconfigured` error (reason class
  `config`) rather than a generic store failure, so a host misconfiguration reads
  differently from a transient outage.
