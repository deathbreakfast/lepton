# lepton verification

How to check that a change did not break this workspace. Identity/session adapters,
SMTP, SMS, auth library APIs (`lepton-auth`), and Orbital auth forms
(`lepton-auth-ui`) live here. Session bridge (`get_session` / `init_auth_resource`)
lives in the host product layer.

This file is a runbook. Scenario catalogs belong next to the e2e packages that
own them (`lepton-auth-ui-e2e`, `lepton-e2e`).

## Environment

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-lepton
```

## Default CI gates

Run from the repository root. Same shape as `.github/workflows/ci.yml`:

```bash
cargo fmt --check \
  -p lepton-auth -p lepton-auth-ui -p lepton-auth-ui-e2e -p lepton-identity \
  -p lepton-smtp -p lepton-sms -p lepton-spectra-telemetry \
  -p lepton-host-adapter -p lepton
cargo clippy --workspace --all-targets --features ssr,full -- -D warnings
cargo test --workspace --features ssr,full
cargo test -p lepton-spectra-telemetry
cargo test -p lepton-smtp --features spectra
cargo test -p lepton-sms --features spectra
cargo check -p lepton-auth --features ssr,full,spectra
cargo check -p lepton-auth-ui --features ssr
cargo check -p lepton-auth --features ssr
cargo check -p lepton-auth-ui --target wasm32-unknown-unknown --features hydrate
cargo leptos end-to-end --project lepton-auth-ui-e2e
```

### rustdoc (CI job `quality`, deny warnings)

Workspace gate (same as `.github/workflows/ci.yml`):

```bash
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --features ssr,full
RUSTDOCFLAGS="-D warnings" cargo doc -p lepton-sms -p lepton-smtp --no-deps --features twilio
```

Focused package gates (library crates without pulling the full UI graph):

```bash
RUSTDOCFLAGS="-D warnings" cargo doc -p lepton-auth --features ssr,full --no-deps
RUSTDOCFLAGS="-D warnings" cargo doc -p lepton-identity --no-deps
RUSTDOCFLAGS="-D warnings" cargo doc -p lepton-host-adapter --features ssr --no-deps
RUSTDOCFLAGS="-D warnings" cargo doc -p lepton-test-support --all-features --no-deps
```

### leptos-lints (CI job `leptos-lints`)

Needs `cargo-dylint` / `dylint-link` 6.0.1 and toolchain `nightly-2025-05-14`
(see `.github/workflows/ci.yml`). Hydrate UI only (`--no-deps`):

```bash
# cargo install cargo-dylint --locked --version 6.0.1
# cargo install dylint-link --locked --version 6.0.1
# rustup toolchain install nightly-2025-05-14 --component rustc-dev,llvm-tools-preview
export CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback
# zerocopy on this pinned nightly needs AVX512 on the host triple (same as orbital CI)
export RUSTFLAGS="-D warnings -Zcrate-attr=feature(stdarch_x86_avx512)"
cargo dylint --all -p lepton-auth-ui --no-deps -- --features hydrate
cargo dylint --all -p lepton-auth-ui-e2e --no-deps -- --features hydrate
```

## Focused package checks

Auth library (includes Photon publish capture helpers under `test-utils`):

```bash
cargo test -p lepton-auth --features ssr,full,test-utils
cargo test -p lepton-e2e --lib --tests
cargo test -p lepton-e2e --test ci_e2e
cargo test -p lepton-test-support --all-features
cargo check -p lepton-e2e --features live-twilio
cargo check -p lepton-e2e --bin lepton-live-oauth --features live-oauth
cargo test -p lepton-auth --features ssr,oauth-google google_
cargo test -p lepton-auth --features ssr,oauth-github github_
```

Twilio adapter crates:

```bash
cargo test -p lepton-sms --features twilio
cargo test -p lepton-smtp --features twilio
```

Playwright auth UI — see `lepton-auth-ui-e2e/README.md`. Includes
`confirm_account.spec.ts` (email → phone → confirm funnel + soft re-entry).
Mailpit must be up (`infra/mailpit/docker-compose.yml`); the e2e host starts the
SMS HTTP sink on `:8099`.

```bash
docker compose -f infra/mailpit/docker-compose.yml up -d
cargo leptos end-to-end --project lepton-auth-ui-e2e
```

Teaching examples (one-shot, exit 0):

```bash
CARGO_BUILD_JOBS=1 cargo run -p lepton-smtp --example noop_send
CARGO_BUILD_JOBS=1 cargo run -p lepton-sms --example noop_send
CARGO_BUILD_JOBS=1 cargo run -p lepton-auth --example password_and_token --features ssr
CARGO_BUILD_JOBS=1 cargo run -p lepton-auth --example auth_flows_noop_smtp --features ssr,email
CARGO_BUILD_JOBS=1 cargo check -p lepton-auth --example auth_contacts_confirm --features ssr
CARGO_BUILD_JOBS=1 cargo check -p lepton-auth --example auth_trust_confirm --features ssr
CARGO_BUILD_JOBS=1 cargo check -p lepton-auth --example auth_totp_enroll --features ssr,totp
CARGO_BUILD_JOBS=1 cargo check -p lepton-auth --example auth_devices --features ssr
CARGO_BUILD_JOBS=1 cargo check -p lepton-auth --example auth_oauth_mock --features ssr,oauth-github
CARGO_BUILD_JOBS=1 cargo run -p lepton-host-adapter --example axum_session_snapshot --features ssr
```

## Optional / gated harnesses

Mailpit (Docker; skipped unless gated):

```bash
./infra/mailpit/smtp_smoke.sh
# or: UF_MAILPIT=1 cargo test -p lepton-smtp --test smtp_mailpit
```

SMS HTTP sink (skipped unless gated):

```bash
UF_SMS_SINK=1 cargo test -p lepton-e2e --test sms_sink_http
```

Live operator CLIs are never CI. Setup and env names: `lepton-e2e/README.md`
(`UF_LEPTON_LIVE_TWILIO`, `UF_LEPTON_LIVE_TOTP`, `UF_LEPTON_LIVE_OAUTH`).

## Notes

- Prefer `*_happy_path` / typed sad-path names so failures are auditable.
- `auth_boundaries` needs `ssr`; token lifecycle tests need `ssr,test-utils,phone`.
- Hosts that load sessions use host product APIs (`get_session` /
  `init_auth_resource`), not a `lepton-auth` product feature.
- Hosts supply plain config; this kit does not pull a secrets manager.

## Action verification (step-up)

```bash
# Unit: seal roundtrip, throttle, scope/mode, replay arithmetic, error prefix
cargo test -p lepton-auth --features "ssr,totp" seal_ -- --nocapture
cargo test -p lepton-auth --features "ssr,totp" step_up -- --nocapture
cargo test -p lepton-auth --lib --features "ssr,totp" throttle::
# Macro expansion + StepUpMode / error-prefix pins (uf-product workspace)
cargo test -p uf-product-macros server_step_up
cargo test -p uf-product --lib step_up_mode_ -- --nocapture
cargo test -p uf-product --lib step_up_error_prefixes -- --nocapture
# Consumer inventory (gauge / neutrino workspaces; monorepo composer sources)
cargo test -p gauge --test product_surface step_up -- --nocapture
cargo test -p neutrino --test product_surface step_up -- --nocapture
# Runnable sketch
cargo run -p lepton-auth --example step_up_totp --features "ssr,totp"
```

Set `LEPTON_TOTP_ALLOW_TEST_SEAL_KEY=1` (or `LEPTON_TOTP_SEAL_KEY` as 64 hex) before SSR hosts that enroll/verify TOTP.
