//! Spectra ops telemetry for Lepton delivery and auth product funnels.
//!
//! Declares the Lepton Spectra family (`store: "lepton"`) with delivery counters,
//! auth funnel counters, and a bounded `lepton_auth_failure` event. There is no
//! process-wide install switch: hosts boot Spectra themselves, then either call
//! the `record_*` / [`log_auth_failure`] helpers or enable the `spectra` feature on
//! `lepton-smtp` / `lepton-sms` / `lepton-auth`.
//!
//! Labels and event fields are **ops-id only**: closed enums / `reason_class`
//! tokens. Recipient, body, emails, phones, user ids, passwords, OTPs, tokens,
//! challenge ids, and free-form error text are never recorded.
//!
//! # Features
//!
//! - **Delivery counters** — Records [`record_email_send`] / [`record_sms_send`] after a
//!   send so ops can chart driver and outcome without PII
//!   ([Record a delivery counter](#record-a-delivery-counter)).
//! - **Auth funnel counters** — Covers signup, sign-in, OAuth, verify, and related
//!   helpers when measuring product auth stages
//!   ([Auth funnel variant](#auth-funnel-variant)).
//! - **Failure events** — Emits [`log_auth_failure`] with bounded `reason_class` tokens
//!   when correlating auth errors without free-form text
//!   ([Auth funnel variant](#auth-funnel-variant)).
//! - **Label sanitizers** — Provides [`emit`] `bound_*` helpers for hosts that map raw
//!   strings before emit ([Record a delivery counter](#record-a-delivery-counter)).
//! - **Transport topics** — Carries Spectra payload DTOs in [`topics`] for cross-process
//!   emit shapes ([Record a delivery counter](#record-a-delivery-counter)).
//!
//! # Getting started
//!
//! ## Record a delivery counter
//!
//! Records a delivery counter after email or SMS send so ops can chart driver and outcome
//! without recipient or body fields. Call after the product send path when Spectra is
//! already booted in the process.
//!
//! Prerequisites: boot Spectra in the host process first (embedded `SQLite`, mem
//! backends, or your Spectra install). Counters are best-effort and never fail
//! the product path.
//!
//! 1. Install Spectra (`Spectra::builder` / host install helper).
//! 2. Call [`record_email_send`] (or [`record_sms_send`]) with driver + outcome.
//! 3. Query or observe `lepton_email_send` / `lepton_sms_send` in your Spectra store.
//!
//! Errors: missing Spectra install means no metric points (emit stays best-effort).
//! Next: [Auth funnel variant](#auth-funnel-variant) or the smoke example.
//!
//! ```rust,ignore
//! use lepton_spectra_telemetry::{record_email_send, EmailSendOutcome};
//!
//! // Host must boot Spectra first (see email_send_record_smoke).
//! record_email_send("noop", EmailSendOutcome::Success);
//! // Observable metric name after query:
//! let metric_name = "lepton_email_send";
//! assert_eq!(metric_name, "lepton_email_send");
//! ```
//!
//! Runnable: `cargo run -p lepton-spectra-telemetry --example email_send_record_smoke`
//!
//! ## Auth funnel variant
//!
//! Auth funnel helpers record signup, sign-in, OAuth, and related stage counters for
//! product funnels. Use them from auth success and MFA paths after Spectra boot.
//!
//! Prerequisites: Spectra boot as above. Errors: same best-effort emit. Next:
//! [`log_auth_failure`] for bounded failure events.
//!
//! ```rust,ignore
//! use lepton_spectra_telemetry::{
//!     record_signin, AuthFactor, AuthOutcome, SigninStage,
//! };
//!
//! record_signin(SigninStage::Password, AuthOutcome::NeedsMfa, "none", AuthFactor::None);
//! record_signin(SigninStage::MfaComplete, AuthOutcome::Success, "none", AuthFactor::Totp);
//! let metric_name = "lepton_signin";
//! assert_eq!(metric_name, "lepton_signin");
//! ```
//!
//! OAuth:
//!
//! ```rust,ignore
//! use lepton_spectra_telemetry::{
//!     record_oauth, AuthOutcome, OAuthIntentLabel, OAuthProviderLabel, OAuthStage,
//! };
//!
//! record_oauth(
//!     OAuthProviderLabel::Google,
//!     OAuthIntentLabel::Signup,
//!     OAuthStage::Complete,
//!     AuthOutcome::Success,
//!     "none",
//! );
//! ```
//!
//! # Feature flags
//!
//! This crate has no Cargo feature flags. Optional emit from adapters uses the
//! `spectra` feature on `lepton-smtp`, `lepton-sms`, or `lepton-auth`.
//!
//! # Further reading
//!
//! - [Record a delivery counter](#record-a-delivery-counter) — first success
//! - [`emit`] — bounded helpers and sanitizers
//! - [`helpers`] — typed schema helpers
//! - [`topics`] — transport DTOs

#![allow(clippy::too_long_first_doc_paragraph)]

/// Bounded emit helpers (delivery + auth funnels + failure events).
pub mod emit;
/// Typed emit helpers from Lepton Spectra schemas.
pub mod helpers;
// macro-generated Spectra schema types; documented via each schema's `description`
#[allow(missing_docs)]
mod schemas;
/// Transport `*Payload` / `*_TOPIC` DTOs from Lepton Spectra schemas.
pub mod topics;

pub use emit::{
    bound_email_driver, bound_error_class, bound_oauth_provider, bound_optional_channel,
    bound_optional_provider, bound_sms_driver, bound_verify_channel, log_auth_failure,
    record_account, record_bot, record_contact, record_device, record_email_send,
    record_identity_delete, record_oauth, record_password_reset, record_signin, record_signup,
    record_sms_send, record_step_up, record_totp, record_verify, AccountOperation, AuthFactor,
    AuthFailureFlow, AuthOutcome, BotOperation, ContactOperation, DeviceKind, DeviceOperation,
    EmailSendOutcome, IdentityDeleteOperation, OAuthIntentLabel, OAuthProviderLabel, OAuthStage,
    PasswordResetStage, SigninStage, SmsSendOutcome, StepUpPath, TotpOperation, VerifyChannel,
    VerifyStage,
};
pub use helpers::*;
pub use topics::*;
