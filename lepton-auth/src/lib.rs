//! Server functions, multi-factor challenges, OAuth, password policy, and tokens for
//! Unified Field hosts.
//!
//! Inject delivery with [`provide_auth_services`], gate product server fns with
//! [`require_auth_user`], and issue challenges through [`FactorChallengeService`].
//! Form UI lives in [`lepton_auth_ui`](../lepton_auth_ui/index.html) (Orbital). Compose
//! request context with **higgs** / **higgs-host**.
//!
//! # Features
//!
//! - **Injected delivery services** — Provides injected email/SMS and a public base URL through
//!   [`services`] so send paths resolve adapters at runtime. Use this when wiring SSR
//!   boot before any verification mail ([Boot delivery](#boot-delivery-email-only)).
//! - **Authenticated server fns** — Gates product server functions on the session with
//!   [`require_auth_user`], then opens user-scoped Valence via [`user_valence`] (or
//!   [`higgs_ctx`] without the gate). Reach for this when a `#[server]` fn must know
//!   who is calling ([Authenticated server fn](#authenticated-server-fn-current-user)).
//! - **Factors** — Issues and verifies email/SMS OTP and TOTP through [`factor`] /
//!   [`FactorChallengeService`] when a flow needs a second factor
//!   ([`factor` Examples](factor/index.html#examples)).
//! - **Action verification (step-up)** — Opens a short session sudo window with
//!   [`verify_totp_for_session`], asserts it with [`require_recent_verification`],
//!   or demands a one-shot code with [`verify_fresh_totp`] for break-glass paths
//!   ([Verify TOTP for a sudo window](#verify-totp-for-a-sudo-window)).
//! - **Signup, OAuth, contacts, and devices** — Covers account creation and linked
//!   identity surfaces in [`signup_api`], [`oauth`], [`contacts`], and [`devices`]
//!   (wipe/erase under [`identity_delete`]; [Examples](#examples)).
//! - **Tokens and policy** — Provides one-time tokens ([`token_helpers`]) and password /
//!   audit helpers ([`security`]) for reset and policy checks
//!   ([Boot delivery](#boot-delivery-email-only)).
//! - **Durable delivery** — Enqueues mail/SMS through Boson when `boson-delivery` is on
//!   so retries survive process restarts ([Examples](#examples)).
//! - **Auth UI actions** — Exposes [`actions`] server functions consumed by
//!   [`lepton_auth_ui`](../lepton_auth_ui/index.html). Mount the shell at
//!   [Mount `AuthDialog`](../lepton_auth_ui/index.html#mount-authdialog-shell).
//! - **Session backend** — Documents axum-login + higgs snapshot wiring on
//!   [`lepton_host_adapter`](../lepton_host_adapter/index.html#host-wiring) when the
//!   host owns cookies and login.
//!
//! Also on this crate: live verification status ([`verification`], [`events`]),
//! session bag keys ([`session_binding`]), referer helpers ([`routes`]), and SMS
//! adapters via [`lepton_sms`](../lepton_sms/index.html).
//!
//! # Getting started
//!
//! ## Boot delivery (email-only)
//!
//! Boot delivery injects email (and optionally SMS) plus a public base URL once at SSR
//! startup so verification and reset sends can resolve adapters later. Call this from the
//! host boot path before serving requests.
//!
//! Prerequisites: `lepton-auth` with `features = ["ssr", "email"]`, and a mail adapter
//! (Noop for CI, SMTP for Mailpit/relay).
//!
//! 1. Build an [`EmailDeliveryService`](../lepton_smtp/trait.EmailDeliveryService.html) via
//!    [`EmailServiceBuilder`](../lepton_smtp/struct.EmailServiceBuilder.html).
//! 2. [`LeptonAuthServicesBuilder::email`] + [`LeptonAuthServicesBuilder::public_base_url`] →
//!    [`LeptonAuthServicesBuilder::build`].
//! 3. Call [`provide_auth_services`] once at SSR boot.
//! 4. Later extracts use [`auth_services`]; missing context is
//!    [`LeptonAuthServicesError::NotInContext`].
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use lepton_auth::services::{
//!     provide_auth_services, LeptonAuthServicesBuilder, LeptonAuthServicesError,
//! };
//! use lepton_smtp::{EmailServiceBuilder, SmtpConfig};
//!
//! // Cargo.toml: lepton-auth = { features = ["ssr", "email"] }
//!
//! let email = EmailServiceBuilder::new()
//!     .smtp(
//!         SmtpConfig::builder()
//!             .host("127.0.0.1")
//!             .port(1025)
//!             .use_tls(false)
//!             .from_email("noreply@example.test")
//!             .build()?,
//!     )
//!     .build()?;
//! provide_auth_services(
//!     Arc::new(
//!         LeptonAuthServicesBuilder::new()
//!             .email(email)
//!             .public_base_url("http://127.0.0.1:3000")
//!             .build()?,
//!     ),
//! );
//! let resolved = lepton_auth::auth_services();
//! assert!(
//!     resolved.is_ok()
//!         || matches!(
//!             resolved.err(),
//!             Some(LeptonAuthServicesError::NotInContext)
//!         )
//! );
//! ```
//!
//! Runnable: `cargo run -p lepton-auth --example auth_flows_noop_smtp --features ssr,email`
//!
//! ## Authenticated server fn (current user)
//!
//! Product server functions gate on the session user, then open a user-scoped Valence.
//! [`require_auth_user`] returns higgs context plus the signed-in
//! [`User`](../lepton_host_adapter/struct.User.html). [`user_valence`] builds Valence for
//! that actor. Use [`higgs_ctx`] when you need context without the auth gate.
//!
//! Errors: unauthenticated callers get `ServerFnError` from [`require_auth_user`].
//! Next: query with the returned Valence, or mount UI via
//! [`lepton_auth_ui`](../lepton_auth_ui/index.html#mount-authdialog-shell).
//!
//! ```rust,ignore
//! use lepton_auth::{require_auth_user, user_valence};
//! use leptos::prelude::*;
//!
//! #[server]
//! async fn my_profile_id() -> Result<String, ServerFnError> {
//!     let (ctx, auth_user) = require_auth_user().await?;
//!     let valence = user_valence(&ctx)?;
//!     assert!(!auth_user.id.to_string().is_empty());
//!     let _ready = &valence; // user-scoped Valence for follow-on queries
//!     Ok(auth_user.id.to_string())
//! }
//! ```
//!
//! ## Verify TOTP for a sudo window
//!
//! Action verification opens a short session sudo window after a successful TOTP
//! check so sensitive product mutations can require recent proof without tying that
//! proof to login MFA. Call [`verify_totp_for_session`] from a dedicated prompt
//! server fn at the start of a critical flow; gated mutations then assert the
//! window with [`require_recent_verification`] (or the product macro `step_up` /
//! `uf_product::permissions::require_step_up`) on each request.
//!
//! Prerequisites: `features = ["ssr", "totp"]`, an enabled `TotpFactor`, and
//! `LEPTON_TOTP_SEAL_KEY` (64 hex) or `LEPTON_TOTP_ALLOW_TEST_SEAL_KEY=1` in tests.
//!
//! 1. Prompt: [`verify_totp_for_session`] with [`StepUpScope::SensitiveMutation`] and the code.
//! 2. Gate: [`require_recent_verification`] inside the mutation (or `step_up` / `require_step_up("window")`).
//! 3. Map failures through [`StepUpError::to_server_fn_error`] (`STEP_UP:<reason_class>:…`).
//!
//! ```rust,ignore
//! use lepton_auth::{
//!     require_recent_verification, verify_fresh_totp, verify_totp_for_session,
//!     StepUpScope,
//! };
//!
//! // Dedicated prompt (opens a 300s session window).
//! async fn open_window(code: String) -> Result<(), leptos::prelude::ServerFnError> {
//!     verify_totp_for_session(StepUpScope::SensitiveMutation, &code)
//!         .await
//!         .map_err(|e| e.to_server_fn_error())?;
//!     Ok(())
//! }
//!
//! // Gated mutation (window mode).
//! async fn sensitive_mutation() -> Result<(), leptos::prelude::ServerFnError> {
//!     require_recent_verification(StepUpScope::SensitiveMutation)
//!         .await
//!         .map_err(|e| e.to_server_fn_error())?;
//!     Ok(())
//! }
//!
//! // Fresh mode ignores any open window.
//! async fn break_glass(code: String) -> Result<(), leptos::prelude::ServerFnError> {
//!     verify_fresh_totp(&code)
//!         .await
//!         .map_err(|e| e.to_server_fn_error())?;
//!     Ok(())
//! }
//! ```
//!
//! Variants:
//!
//! - **Enrollment** — No enabled `TotpFactor` yields `totp_enrollment_required`. Send the
//!   user to Account Settings, then retry the prompt.
//! - **Expiry** — After [`STEP_UP_TTL_SECS`] (300s), or when the session / auth-hash no
//!   longer matches, [`require_recent_verification`] returns `step_up_expired` or
//!   `step_up_required`. Open the prompt again.
//! - **Fresh** — [`verify_fresh_totp`] demands a code on that call even when a window is
//!   open (break-glass reveal, Super User membership, handoff finalize). Same-step
//!   replay and attempt lockout return `step_up_invalid` / `step_up_rate_limited`.
//!
//! Runnable: `cargo run -p lepton-auth --example step_up_totp --features ssr,totp`.
//! UI retry: `lepton-auth-ui` `StepUpController` / `StepUpDialog`.
//!
//! ## Typical verification flow (backend)
//!
//! 1. Inject SMTP/SMS via [`provide_auth_services`] at SSR boot.
//! 2. Issue challenges with [`FactorChallengeService`] (feature-gated per channel).
//! 3. Consume tokens / codes; success marks the contact verified and publishes Photon.
//! 4. Refetch [`verification::verification_status`] with the challenge id.
//!
//! # Feature flags
//!
//! | Feature | Role |
//! |---------|------|
//! | `ssr` | Server functions, token/password helpers, Valence/higgs helpers |
//! | `email` | Verification / reset **mail** delivery (`lepton-smtp`); not email-as-login |
//! | `phone` | SMS OTP + `lepton-sms` adapters |
//! | `totp` / `two_factor` | TOTP enroll / verify (`totp-rs`) + QR SVG (`qrcode`) on SSR |
//! | `webauthn` | `WebAuthn` passkey ceremony for `AuthDevice` (`webauthn-rs`) |
//! | `oauth-google` | Live Google authorize URL + token/userinfo exchange; mock provider via `use_mock_provider` |
//! | `oauth-github` | Live GitHub authorize URL + token/user/emails exchange; mock provider via `use_mock_provider` |
//! | `full` | `email` + `phone` + `totp` + oauth flags + `webauthn` |
//! | `boson-delivery` | Durable email/SMS send + attempt log (`delivery` module, TTL 7d) |
//! | `spectra` | Emit auth funnel Spectra counters / `lepton_auth_failure` via `lepton-spectra-telemetry` (label tokens only; never emails, codes, or free-form errors) |
//! | `hydrate` | Client hydration helpers (`token_url`; hosts provide the session bridge) |
//! | `test-utils` | Photon publish capture for integration tests |
//!
//! Hosts that want today's mail behavior: `features = ["ssr", "email"]` (or `ssr,full`).
//! Account signup is available under `ssr` by default (UI in `lepton-auth-ui`). Private
//! hosts set `UF_LEPTON_SIGNUP_DISABLED=1` ([`signup_policy`]).
//!
//! # Integration checklist
//!
//! 1. Call [`provide_auth_services`] at boot. Send paths return
//!    [`LeptonAuthServicesError::NotInContext`] when missing.
//! 2. Wire axum-login [`Backend`](../lepton_host_adapter/struct.Backend.html) + session
//!    middleware from `lepton-host-adapter`; provide higgs in the Leptos route context.
//! 3. Resolve secrets **outside** this crate (plain strings into builders). This crate
//!    does not load a secrets manager.
//! 4. Mount photon-leptos WS + Origin allowlist for live verification UI (host obligation).
//! 5. Validate SMTP with `infra/mailpit` when needed (`UF_MAILPIT=1`).
//! 6. For private deploys, set `UF_LEPTON_SIGNUP_DISABLED=1` and hide sign-up CTAs.
//! 7. Multi-instance hosts: persistent session store + shared OAuth CSRF (see kit `SECURITY.md`).
//!
//! Auth UI server functions in [`actions`] register through Leptos
//! `generate_route_list` / `leptos_routes_with_context`.
//!
//! # Examples
//!
//! Start with [Boot delivery](#boot-delivery-email-only). [`factor` Examples](factor/index.html#examples)
//! and `examples/password_and_token` cover challenge issue and verify flows. Runnable hosts:
//! `examples/auth_flows_noop_smtp`, `examples/auth_totp_enroll`; durable delivery in
//! `tests/delivery_attempt.rs`.
//!
//! # Further reading
//!
//! - Crate [`README.md`](https://github.com/unified-field-dev/lepton/blob/main/lepton-auth/README.md)
//! - [`lepton_auth_ui`](../lepton_auth_ui/index.html) — dialogs and embeddable forms
//! - [`lepton_sms`](../lepton_sms/index.html) — SMS adapters
#![recursion_limit = "256"]

/// Server-side account settings overview + mutation logic.
pub mod account_api;
/// `#[server]` functions backing the auth UI.
pub mod actions;
/// Multi-email / multi-phone contacts and primary selection (`ssr`).
#[cfg(feature = "ssr")]
pub mod contacts;
/// Durable Boson delivery + [`DeliveryAttempt`](lepton_host_adapter::generated::DeliveryAttempt) log.
#[cfg(all(feature = "ssr", feature = "boson-delivery"))]
pub mod delivery;
/// Trusted browser / WebAuthn device APIs and DTOs.
pub mod devices;
/// Server-side email dispatch for verification/reset flows (`email` feature).
#[cfg(feature = "email")]
pub mod email_delivery;
/// Photon topics for verification completion (best-effort publish).
pub mod events;
/// Multi-factor challenge issue / verify (email OTP, SMS OTP, TOTP).
pub mod factor;
/// Guarded user/email/membership deletes and account erase (`ssr`).
#[cfg(feature = "ssr")]
pub mod identity_delete;
/// OAuth login / signup / link (`ssr`; mock provider + provider flags).
#[cfg(feature = "ssr")]
pub mod oauth;
/// Route path constants shared between server routes and client-side links.
pub mod paths;
/// Redirect/referer path parsing and sanitization for post-auth navigation.
pub mod routes;
/// Password policy checks, credential audit logging, and random tokens.
pub mod security;
/// Injected email/SMS/public-URL services for auth send paths.
#[cfg(feature = "ssr")]
pub mod services;
/// Session bag keys for AuthDevice binding (`ssr`).
#[cfg(feature = "ssr")]
pub mod session_binding;
/// Login MFA pending bag + complete / skip (`ssr`).
#[cfg(feature = "ssr")]
pub mod session_mfa;
/// Signup library API (`create_pending_user` + session `execute`).
#[cfg(feature = "ssr")]
pub mod signup_api;
/// Open-signup enablement (`UF_LEPTON_SIGNUP_DISABLED`).
pub mod signup_policy;
/// Session-bound TOTP step-up / sudo window (`ssr` + `totp`).
#[cfg(all(feature = "ssr", feature = "totp"))]
pub mod step_up;
/// One-time token issuance and lifecycle checks (verification/reset).
pub mod token_helpers;
/// Client-side one-time token URL helpers (fragment-first; legacy query strip).
#[cfg(feature = "hydrate")]
pub mod token_url;
/// TOTP enroll / disable / recovery codes (`totp`).
#[cfg(all(feature = "ssr", feature = "totp"))]
pub mod totp;
/// Confirm / id-verify library APIs (`ssr`; no product UI).
#[cfg(feature = "ssr")]
pub mod trust;
/// Challenge-keyed verification status server fn (+ optional Photon synced refetch).
pub mod verification;
/// Browser `navigator.credentials` WebAuthn JSON helpers (`hydrate`).
#[cfg(feature = "hydrate")]
pub mod webauthn_browser;

#[cfg(all(feature = "ssr", feature = "spectra"))]
mod spectra_emit;

#[cfg(feature = "ssr")]
mod ssr_support;

#[cfg(feature = "ssr")]
pub use ssr_support::{extract_auth_user, higgs_ctx, require_auth_user, user_valence};

#[cfg(all(feature = "ssr", feature = "totp"))]
pub use factor::verify_totp_against_sealed;
#[cfg(feature = "ssr")]
pub use factor::{FactorChallengeError, FactorChallengeService};
#[cfg(feature = "ssr")]
pub use services::{
    auth_services, provide_auth_services, LeptonAuthServices, LeptonAuthServicesBuilder,
    LeptonAuthServicesError,
};
#[cfg(all(feature = "ssr", feature = "totp"))]
pub use step_up::{
    clear_window, require_recent_verification, verify_fresh_totp, verify_totp_for_session,
    StepUpError, StepUpMode, StepUpOutcome, StepUpScope, STEP_UP_TTL_SECS,
};
#[cfg(all(feature = "ssr", feature = "phone"))]
pub use token_helpers::{generate_phone_otp_code, IssuedPhoneChallenge, PHONE_OTP_DIGIT_LEN};

pub use events::VerificationKind;
pub use factor::FactorChallengeKind;
pub use verification::{verification_status, VerificationStatusSnapshot};
