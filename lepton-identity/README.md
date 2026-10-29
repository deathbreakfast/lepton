# lepton-identity

Identity Valence models and Argon2 password hashing for headless and SSR hosts.
Generated tables ship without Leptos so workers and adapters share one schema surface.

**Source of truth for teaching:** `cargo doc -p lepton-identity --open` (crate root).

```toml
lepton-identity = { git = "https://github.com/unified-field-dev/lepton", package = "lepton-identity" }
```

## Features

- **Identity models** — `generated` Valence types for users, accounts, contacts, devices
- **Password hashing** — `auth::hash_password` (Argon2 PHC)
- **Signup ownership** — `ownership::ensure_signup_identity_ownership`
- **Product composition** — hop from a product row to `User`
- **Service users** — `ServiceUserAccount` model, `service_users::ServiceUserId` actor mapping, handle rules, and the host-installed `service_users::ServiceUserGate`. Users, service users, and System are different actors; a service user never satisfies `AUTHENTICATED`, and authenticating a service user is the host's job (preview)

## Getting started

```rust
use lepton_identity::auth::hash_password;

let phc = hash_password("ValidPass123!").expect("hash");
assert!(phc.starts_with("$argon2"));
```

## Feature flags

| Feature | Effect |
|---------|--------|
| `db-sqlite` (default) | Embedded SQLite engine id |
| `db-hybrid` | Hybrid engine for host routers |
| `test-utils` | Fault-injection hooks for contract tests |

Session / axum-login wiring lives in `lepton-host-adapter`. Full auth UI and SMTP live in
the [lepton](https://github.com/unified-field-dev/lepton) workspace.

## Verify

```bash
export CARGO_BUILD_JOBS=1
cargo test -p lepton-identity
```

## License

MIT. See the workspace [LICENSE](../LICENSE).
