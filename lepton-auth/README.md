# lepton-auth

Server functions, multi-factor challenges, OAuth, password policy, and tokens for
Unified Field hosts.

**Source of truth for teaching:** `cargo doc -p lepton-auth --features ssr,full --open`.

## Features

- **Boot delivery** — Provides injected email/SMS and a public base URL via `services` at SSR boot.
- **Authenticated server fns** — Gates with `require_auth_user` and opens Valence via `user_valence`.
- **Factors** — Issues and verifies email/SMS OTP and TOTP through `FactorChallengeService`.
- **Signup, OAuth, contacts, and devices** — Library APIs plus `actions` server functions for account flows.
- **Tokens and policy** — Covers `token_helpers` and `security` for reset and policy checks.
- **Durable delivery** — Enqueues mail/SMS under the `boson-delivery` feature for retries across restarts.

Teaching destinations and call sequences live in crate rustdoc (not this README).

## Getting started

```bash
CARGO_BUILD_JOBS=1 cargo run -p lepton-auth --example auth_flows_noop_smtp --features ssr,email
CARGO_BUILD_JOBS=1 cargo run -p lepton-auth --example password_and_token --features ssr
```

See crate rustdoc **Getting started** (Boot delivery) for the in-docs first-success path.

## Feature flags

| Feature | Role |
|---------|------|
| `ssr` | Server functions, Valence helpers (no delivery deps); includes Signup |
| `email` | Verification / reset **mail** (`lepton-smtp`); not email-as-login |
| `phone` | SMS OTP + `lepton-sms` |
| `totp` / `two_factor` | TOTP verify + enroll (`totp-rs`) |
| `webauthn` | WebAuthn passkey ceremony for `AuthDevice` (`webauthn-rs`) |
| `oauth-google` | Live Google authorize URL + token/userinfo exchange |
| `oauth-github` | Live GitHub authorize URL + token/user/emails exchange |
| `oauth-microsoft` | Live Microsoft (Entra ID) authorize URL + token/userinfo exchange; tenant via `microsoft_tenant` (default `common`) |
| `full` | `email` + `phone` + `totp` + oauth flags + `webauthn` |
| `boson-delivery` | Durable email/SMS send + attempt log |
| `spectra` | Auth funnel Spectra counters via `lepton-spectra-telemetry` |
| `hydrate` | Client hydration helpers |
| `test-utils` | Publish-capture helpers for integration tests |

Mail hosts: `features = ["ssr", "email"]`. CI / full channels: `ssr,full`.

## Integration checklist

1. `provide_auth_services(LeptonAuthServicesBuilder…)` at boot — fail closed when missing.
2. Supply secrets as plain strings from the host. This crate does not load a secrets manager.
3. Mount photon-leptos `ws_router` + Origin allowlist when using live verification UI.
4. Prefer Mailpit (`../infra/mailpit`) for real SMTP; CI stays Docker-free via Noop.

## Further reading

- Crate rustdoc (`cargo doc -p lepton-auth --features ssr,full --open`)
- [`examples/README.md`](examples/README.md)
- [`../docs/VERIFICATION.md`](../docs/VERIFICATION.md)
