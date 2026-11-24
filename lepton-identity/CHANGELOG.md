# Changelog

All notable changes to `lepton-identity` are recorded here.

## [Unreleased]

### Added

- `tokens` module: one token model for people and service users. `PersonalToken` model
  (`personal_token` table, owner-only, deleted with its person) with the
  `PERSONAL_TOKEN_IMMUTABLE` rule. `ApiScope` (`api:action`) and `TokenLifetime` (30 or 90
  days). `tokens::verify_bearer_token` returns a `VerifiedToken`: who the token acts as
  (`TokenPrincipal::Person` or `TokenPrincipal::ServiceUser`) and its scopes.
  `tokens::record_token_use` writes `last_used_at` as the token's own actor.
- `service_user_token` gains `scopes`, `kind` (`manual` or `device`), `device_id` and
  `last_used_at` (schema version 0.2.0), and the `SERVICE_USER_TOKEN_TOUCH` rule, which lets
  a service user record its own token's last use and change nothing else.
- `ServiceUserActivity` model (`service_user_activity` table): an append-only history of
  each service user's lifecycle changes and token events, readable by the owner and by
  manage-any users. Rules `SERVICE_USER_ACTIVITY_WRITE` and
  `SERVICE_USER_ACTIVITY_APPEND_ONLY` guard it.
- `LinkedIdentity` and `OauthPendingState` accept `microsoft` as a provider
  (schema version 0.2.0).
- `protected_fields` update rules keep `User.status`, `user_type`, `confirmed_at`,
  `id_verified_at`, `password_hash` and `Account.plan`, `status` system-only to write.
  `stored_password_hash` reads the stored hash for the signed-in user's own password checks.
- Personal access tokens for service users: the `service_user_token` table,
  `service_users::verify_bearer_token` (shape, hash, revoked, expiry, and the
  service user's active status), and the `SERVICE_USER_TOKEN_CREATE` and
  `SERVICE_USER_TOKEN_IMMUTABLE` privacy rules. Only a SHA-256 hash of the
  secret is stored.
- `config::install_service_users_per_owner` lets a host set the service user
  limit per owner once at boot; `config::service_users_per_owner` reads it and
  falls back to `DEFAULT_SERVICE_USERS_PER_OWNER` (10).
- `ServiceUserId` and `ServiceUserHandle` implement `Serialize` and
  `Deserialize`. Both travel as plain strings and deserialize through `parse`,
  so invalid values are rejected.

### Changed

- Lepton tokens now start with `lptk_` (`tokens::LeptonToken`). The bearer check accepts
  nothing else, so `lpt_` service user tokens stop verifying; mint new ones.
  `service_users::ServiceUserToken`, `ServiceUserTokenParseError`, `VerifiedServiceUser`,
  `TOKEN_PREFIX` and `hash_token_secret` moved to or were replaced by the `tokens` module;
  `service_users::verify_bearer_token` re-exports the new check.
- `SERVICE_USER_TOKEN_IMMUTABLE` also blocks changes to `scopes`, `kind`, `device_id` and
  `created_at`, and now compares stored timestamps correctly.
- `ProfilePhoto` update and delete now match the session user against `uploaded_by`
  through `OWNER_BY_UPLOADED_BY`. The old rule read a `user` field the table
  doesn't have, so owners were refused. The schema version is 0.2.0.
- `User.password_hash` is system-only to read; the owner no longer sees it on a loaded
  `User`. `User` is now schema 0.4.0 and `Account` 0.6.0.
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
