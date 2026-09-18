# Lepton

[![CI](https://github.com/unified-field-dev/lepton/actions/workflows/ci.yml/badge.svg)](https://github.com/unified-field-dev/lepton/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[GitHub](https://github.com/unified-field-dev/lepton) · `cargo doc -p lepton-auth --open`

Auth for Leptos hosts: Valence user and contact shapes, email and phone verification,
backup emails/phones, TOTP (with recovery codes), Google and GitHub OAuth for signup
and sign-in, trusted-browser devices, and Leptos UI under `/auth` (sign-in, sign-up,
password reset). Delivery adapters and **higgs** / **higgs-host** session context plug
in at the host.

Wire delivery once at SSR boot. Server fns then send with the injected adapter — no env reads on the hot path.

```rust,ignore
use std::sync::Arc;
use lepton_auth::email_delivery::ssr::send_verification_token_email;
use lepton_auth::services::{provide_auth_services, LeptonAuthServicesBuilder};
use lepton_smtp::{EmailServiceBuilder, VerificationEmailFlow};

let email = EmailServiceBuilder::new().smtp(smtp_cfg).build()?;
provide_auth_services(Arc::new(
    LeptonAuthServicesBuilder::new()
        .email(email)
        .public_base_url("https://app.example.com")
        .build()?,
))?;

// Later, in a server fn:
let receipt = send_verification_token_email(
    "alex@example.com",
    Some("Alex Rivera"),
    &token_id,
    VerificationEmailFlow::Signup,
)
.await?;
// Observable: receipt / Ok from the injected adapter (see lepton-auth Getting started).
let _ = receipt;
```

## Getting started

```toml
[dependencies]
lepton-auth = { git = "https://github.com/unified-field-dev/lepton", tag = "v0.1.0", default-features = false }
lepton-auth-ui = { git = "https://github.com/unified-field-dev/lepton", tag = "v0.1.0", package = "lepton-auth-ui", default-features = false }
lepton-smtp = { git = "https://github.com/unified-field-dev/lepton", tag = "v0.1.0", package = "lepton-smtp" }
lepton-sms = { git = "https://github.com/unified-field-dev/lepton", tag = "v0.1.0", package = "lepton-sms" }
lepton-identity = { git = "https://github.com/unified-field-dev/lepton", tag = "v0.1.0", package = "lepton-identity" }
lepton-host-adapter = { git = "https://github.com/unified-field-dev/lepton", tag = "v0.1.0", package = "lepton-host-adapter" }
# Shell / app UI is a separate consuming layer built on top of these crates.
# Auth channels: lepton-auth features = ["ssr", "email"] or ["ssr", "full"]
```

SMS uses `lepton-sms` (Noop/Test; optional `twilio`). Shell and app UI mount
on top of these crates as a separate consuming layer.

## Features

| Area | What ships |
|------|------------|
| User / account | Valence `User`, `Account`, `AccountEmail`, `AccountPhone`, profile; login via email address |
| Email / phone verify | One-time tokens and SMS OTP; stock verify/reset mail helpers |
| Backup contacts | Add verified emails/phones, promote primary, then confirm the account |
| Two-factor | TOTP enroll / verify / disable; recovery codes returned once |
| OAuth | Google and GitHub signup, sign-in, and Account Settings link/unlink (`oauth-google` / `oauth-github`); mock provider for CI |
| Devices | Trusted-browser register / confirm / list / revoke; WebAuthn register / assert (`webauthn` feature) |
| UI (`lepton-auth-ui`) | `AuthDialog`, `StepUpDialog` / `StepUpController`, `SigninContent`, `SignupContent`, password-reset dialogs and content, logout |
| Delivery | Builder-first SMTP and SMS; inject once with `provide_auth_services` |
| Spectra | Optional `lepton-spectra-telemetry` delivery + auth funnel counters (`spectra` on smtp/sms/auth) |
| Live status | Photon `VerificationCompleted` + `verification_status` refetch |

TOTP enroll UI and OAuth link/unlink ship on the host's Account Settings
surface. Per-op re-auth ships as `lepton_auth_ui::StepUpDialog` (library
verify in `lepton-auth::factor`). The product shell mounts the dialog for
future host apps; Account Settings does not drive step-up today. Wipe keeps
its own password (+ TOTP) ladder.

## Crates

- [`lepton-identity`](lepton-identity/README.md) / [`lepton-host-adapter`](lepton-host-adapter/README.md) — Valence identity schemas and host session adapters
- [`lepton-smtp`](lepton-smtp/README.md) — builder-first email delivery (optional `twilio` = SendGrid Mail Send; `spectra` = delivery counters)
- [`lepton-sms`](lepton-sms/README.md) — SMS Noop/Test + optional live Twilio Messages (`features = ["twilio"]`; `spectra` = delivery counters)
- [`lepton-spectra-telemetry`](lepton-spectra-telemetry/README.md) — Lepton Spectra family (delivery + auth funnel counters / failure events)
- [`lepton-auth`](lepton-auth/README.md) — server fns, contacts/trust/devices/oauth/totp, Photon status (no Orbital); optional `spectra` emit
- [`lepton-auth-ui`](lepton-auth-ui/README.md) — Orbital form components over `lepton-auth` actions
- [`lepton-auth-ui-e2e`](lepton-auth-ui-e2e/README.md) — library Playwright host (`publish = false`)
- [`lepton-e2e`](lepton-e2e/README.md) — CI e2e signup/verify + device/TOTP + OAuth; live Twilio / TOTP / OAuth CLIs (`publish = false`)
- [`lepton-test-support`](lepton-test-support/README.md) — test-only user builders + seed scenarios / HTTP (`publish = false`)

## Examples

- Auth primitives (password policy, tokens, noop SMTP) — no database required:
  [`lepton-auth/examples/README.md`](lepton-auth/examples/README.md).
- Host session wiring (`Backend` + `session_snapshot_middleware`) — SQLite `:memory:`:
  [`lepton-host-adapter/examples/README.md`](lepton-host-adapter/examples/README.md).

## Verify

```bash
export CARGO_BUILD_JOBS=1
cargo fmt --check \
  -p lepton-auth -p lepton-identity -p lepton-smtp -p lepton-sms \
  -p lepton-host-adapter -p lepton -p lepton-test-support
cargo clippy --workspace --all-targets --features ssr,full -- -D warnings
cargo test --workspace --features ssr,full
cargo test -p lepton-e2e --lib --tests
cargo test -p lepton-test-support --all-features
cargo test -p lepton-sms --features twilio
cargo test -p lepton-smtp --features twilio
cargo check -p lepton-auth --features ssr
cargo check -p lepton-e2e --features live-twilio
cargo check -p lepton-e2e --bin lepton-live-oauth --features live-oauth
```

How to re-run the gates: [`docs/VERIFICATION.md`](docs/VERIFICATION.md).

## License

MIT. See [LICENSE](LICENSE), [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
