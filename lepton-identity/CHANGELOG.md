# Changelog

All notable changes to `lepton-identity` are recorded here.

## [Unreleased]

### Added

- `config::install_service_users_per_owner` lets a host set the service user
  limit per owner once at boot; `config::service_users_per_owner` reads it and
  falls back to `DEFAULT_SERVICE_USERS_PER_OWNER` (10).
- `ServiceUserId` and `ServiceUserHandle` implement `Serialize` and
  `Deserialize`. Both travel as plain strings and deserialize through `parse`,
  so invalid values are rejected.

### Changed

- `ServiceUserHandle::parse` refuses handles that end in a dash, such as
  `spectra-` (`InvalidChar`).

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
