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
//! - **Service users** — Lets a signed-in user create service users they own, then edit,
//!   suspend, resume, or delete them through [`service_users`]. Only the owner, and users the
//!   host's service user gate trusts to manage any service user, can see a service user
//!   ([Create and manage a service user](#create-and-manage-a-service-user)).
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
//! ## Create and manage a service user
//!
//! A service user is a non-human account the signed-in user owns. It gets its own id and acts in
//! Valence as its own service actor, so an agent or integration can work under the service user's
//! name instead of a person's. Call these functions from server functions with the
//! **request** Valence of the signed-in owner; the owner is taken from that actor.
//!
//! Prerequisites: `lepton-auth` with `features = ["ssr"]`; a service user gate installed at
//! boot ([Install the service user
//! gate](../lepton_identity/index.html#install-the-service-user-gate)) that lets this user
//! create service users; the request Valence from [`require_auth_user`] + [`user_valence`];
//! and, for deletes, a Valence deletion dispatcher registered at boot (valence-platform's
//! Chronon deletion orchestrator).
//!
//! 1. [`service_users::create_service_user`] with a handle such as `spectra-agent`, a display
//!    name, and an optional description. The service user starts `active`.
//! 2. [`service_users::update_service_user`] edits the display name or description; owner and
//!    handle never change.
//! 3. [`service_users::suspend_service_user`] / [`service_users::resume_service_user`] pause
//!    and restart it.
//! 4. [`service_users::delete_service_user`] removes it with the standard Valence delete.
//!
//! ```rust,no_run
//! use lepton_auth::service_users::{
//!     create_service_user, delete_service_user, get_service_user, resume_service_user, suspend_service_user, update_service_user, ServiceUserError,
//!     ServiceUserProfileUpdate, NewServiceUser,
//! };
//! use lepton_host_adapter::generated::ServiceUserAccountStatus;
//! use lepton_identity::service_users::ServiceUserId;
//!
//! // `v` is the signed-in owner's request Valence (`user_valence(&ctx)?`).
//! async fn service_user_lifecycle(v: &valence::Valence) -> Result<(), Box<dyn std::error::Error>> {
//!     let service_user = create_service_user(v, NewServiceUser {
//!         handle: "spectra-agent",
//!         display_name: "Spectra agent",
//!         description: Some("Reads product metrics"),
//!     })
//!     .await?;
//!     assert_eq!(service_user.status(), &ServiceUserAccountStatus::Active);
//!     let id = ServiceUserId::parse(service_user.id().ok_or("unsaved service user")?.id())?;
//!
//!     update_service_user(v, &id, ServiceUserProfileUpdate { display_name: Some("Spectra reader"), ..Default::default() }).await?;
//!     assert_eq!(suspend_service_user(v, &id).await?.status(), &ServiceUserAccountStatus::Suspended);
//!     assert_eq!(resume_service_user(v, &id).await?.status(), &ServiceUserAccountStatus::Active);
//!
//!     delete_service_user(v, &id).await?;
//!     assert!(matches!(get_service_user(v, &id).await, Err(ServiceUserError::NotFound)));
//!     Ok(())
//! }
//! ```
//!
//! Errors carry a `reason_class` ([`service_users::ServiceUserError::reason_class`]). The ones
//! a form shows:
//!
//! - **Handle in use**: [`service_users::ServiceUserError::HandleTaken`] carries a free
//!   suggestion such as `spectra-agent-2`; [`service_users::suggest_service_user_handle`]
//!   turns free text into a free handle first.
//! - **Not allowed**: [`service_users::ServiceUserError::CreateNotPermitted`] when the gate
//!   says no, and [`service_users::ServiceUserError::GateNotInstalled`] when the host never
//!   installed one.
//! - **Too many service users**: [`service_users::ServiceUserError::QuotaReached`] once the
//!   owner has as many service users as the host allows
//!   ([`lepton_identity::config::service_users_per_owner`], 10 unless the host sets it);
//!   deleting one frees a slot.
//! - **Someone else's service user**: [`service_users::ServiceUserError::NotFound`]. A service
//!   user the caller may not see looks the same as one that does not exist.
//!
//! Service users, registered or built-in, and anonymous callers get
//! [`service_users::ServiceUserError::NotAUser`], so a service user never manages itself.
//! Deleting the owner's user through [`identity_delete`] deletes their service users.
//!
//! Suspending records the status only. The host refuses a suspended service user when it
//! authenticates one ([Authentication is the host's
//! job](../lepton_identity/index.html#authentication-is-the-hosts-job-preview)).
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
pub mod actions;
#[cfg(feature = "ssr")]
pub mod contacts;
#[cfg(all(feature = "ssr", feature = "boson-delivery"))]
pub mod delivery;
pub mod delivery_settings;
pub mod devices;
#[cfg(feature = "email")]
pub mod email_delivery;
pub mod events;
pub mod factor;
#[cfg(feature = "ssr")]
pub mod identity_delete;
#[cfg(feature = "ssr")]
pub mod oauth;
/// Route path constants shared between server routes and client-side links.
pub mod paths;
/// Redirect/referer path parsing and sanitization for post-auth navigation.
pub mod routes;
pub mod security;
#[cfg(feature = "ssr")]
pub mod service_users;
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
#[cfg(all(feature = "ssr", feature = "totp"))]
pub mod step_up;
pub mod token_helpers;
/// Client-side one-time token URL helpers (fragment-first; legacy query strip).
#[cfg(feature = "hydrate")]
pub mod token_url;
#[cfg(all(feature = "ssr", feature = "totp"))]
pub mod totp;
#[cfg(feature = "ssr")]
pub mod trust;
pub mod verification;
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
    clear_window, load_window, require_recent_verification, verify_code_against_factor,
    verify_fresh_totp, verify_fresh_totp_for_session_user, verify_totp_for_session,
    window_matches_identity, LoadedWindow, StepUpError, StepUpMode, StepUpOutcome, StepUpScope,
    STEP_UP_TTL_SECS,
};
#[cfg(all(feature = "ssr", feature = "phone"))]
pub use token_helpers::{generate_phone_otp_code, IssuedPhoneChallenge, PHONE_OTP_DIGIT_LEN};

pub use events::VerificationKind;
pub use factor::FactorChallengeKind;
pub use verification::{verification_status, VerificationStatusSnapshot};
