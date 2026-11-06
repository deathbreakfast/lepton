//! Multi-factor challenge issuance and verification (email OTP, SMS OTP, TOTP).
//!
//! Channel methods appear when their Cargo features are on (`email`, `phone`, `totp`).
//!
//! Issues and verifies factor challenges through injected [`crate::services::LeptonAuthServices`].
//! Account Settings TOTP enroll UI lives in [`crate::actions::totp`]; the step-up
//! modal ([`StepUpDialog`](../lepton_auth_ui/fn.StepUpDialog.html)) mounts in the host shell.
//!
//! Login MFA at sign-in uses [`crate::session_mfa`] / [`crate::actions::signin`]. Per-op
//! step-up for a sensitive mutation uses this module plus the UI dialog.
//!
//! # When to call
//!
//! | Task | Feature | API |
//! |------|---------|-----|
//! | Issue / verify email OTP | `email` | [`FactorChallengeService::issue_email_otp`], [`FactorChallengeService::verify_email_otp`] |
//! | Issue / verify SMS OTP | `phone` | [`FactorChallengeService::issue_sms_otp`], [`FactorChallengeService::verify_sms_otp`] |
//! | Verify enrolled TOTP | `totp` | [`FactorChallengeService::verify_totp_code`], [`verify_totp_against_sealed`] |
//! | Consume recovery code | `totp` | [`FactorChallengeService::consume_totp_recovery_code`] |
//! | Step-up TOTP or bound device | `totp` | [`FactorChallengeService::verify_totp_or_bound_device`] |
//! | Enroll TOTP | `totp` | [`crate::totp`] |
//! | Step-up before sensitive op | `totp` (or OTP) | [`FactorChallengeService::verify_totp_code`] (strict) + [`StepUpDialog`](../lepton_auth_ui/fn.StepUpDialog.html) |
//!
//! # Examples
//!
//! Step-up TOTP inside a host server fn. Pair with
//! [`StepUpDialog`](../lepton_auth_ui/fn.StepUpDialog.html) so the client collects the code first:
//!
//! ```rust,ignore
//! use lepton_auth::{require_auth_user, FactorChallengeService};
//! use leptos::prelude::*;
//!
//! #[server]
//! async fn delete_billing_method(totp_code: String) -> Result<(), ServerFnError> {
//!     let (ctx, auth_user) = require_auth_user().await?;
//!     let valence = ctx.unsafe_system_valence()?; // TotpFactor secrets
//!     let services = lepton_auth::auth_services()?;
//!     let factors = FactorChallengeService::new(services);
//!     // Critical ops: prefer verify_totp_code (no bound-device skip).
//!     factors
//!         .verify_totp_code(&valence, &auth_user.id, &totp_code)
//!         .await
//!         .map_err(|e| ServerFnError::new(e.to_string()))?;
//!     // … perform the sensitive mutation …
//!     Ok(())
//! }
//! ```
//!
//! Runnable sketch: `examples/step_up_totp`. Enroll path: [`crate::totp`] /
//! `examples/auth_totp_enroll`.

#[cfg(feature = "ssr")]
use std::sync::Arc;

#[cfg(feature = "ssr")]
use thiserror::Error;
#[cfg(feature = "ssr")]
use valence::{RecordId, Valence};

#[cfg(feature = "ssr")]
use crate::services::LeptonAuthServices;

#[cfg(all(feature = "ssr", feature = "email"))]
mod email_otp;
#[cfg(all(feature = "ssr", feature = "phone"))]
mod phone_otp;
#[cfg(all(feature = "ssr", feature = "totp"))]
mod totp;

#[cfg(all(feature = "ssr", feature = "totp"))]
pub use totp::verify_totp_against_sealed;

/// Kind of second-factor / verification challenge to issue or verify.
///
/// Wire-compatible variants stay present even when a channel feature is off;
/// issuing a disabled kind returns [`FactorChallengeError::UnsupportedKind`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FactorChallengeKind {
    /// Email one-time link / OTP via email verification token.
    EmailOtp,
    /// SMS one-time code via phone verification token.
    SmsOtp,
    /// Time-based OTP from an enrolled authenticator.
    Totp,
}

/// Typed errors from [`FactorChallengeService`].
#[cfg(feature = "ssr")]
#[derive(Debug, Error)]
pub enum FactorChallengeError {
    /// Unsupported kind for the requested operation (or feature disabled).
    #[error("reason_class=unsupported_kind: factor challenge kind not supported: {0:?}")]
    UnsupportedKind(FactorChallengeKind),
    /// Auth services missing from context or builder error.
    #[error("reason_class=services: auth services unavailable")]
    Services,
    /// Token / persistence failure (opaque).
    #[error("reason_class=token: token operation failed")]
    Token,
    /// Phone number could not be normalized to a valid form.
    #[error("reason_class=invalid_phone: enter a valid phone number")]
    InvalidPhone,
    /// Delivery (email / SMS) failure (no recipient/body; may include provider `reason_class`).
    #[error("reason_class=delivery: delivery failed ({0})")]
    Delivery(String),
    /// TOTP factor missing or not enabled.
    #[error("reason_class=totp_unavailable: totp factor not available")]
    TotpUnavailable,
    /// Presented TOTP code was rejected.
    #[error("reason_class=mismatch: invalid totp code")]
    TotpInvalid,
    /// Sealed secret could not be decoded / used (never includes the secret or code).
    #[error("reason_class=totp_secret: totp secret error")]
    TotpSecret,
    /// Too many wrong email codes; the token is locked until the lockout ends.
    #[error("reason_class=rate_limited: too many attempts; try again later")]
    RateLimited,
    /// User row missing after a successful phone consume.
    #[error("reason_class=user: user not found")]
    UserMissing,
}

#[cfg(feature = "ssr")]
impl FactorChallengeError {
    /// Stable reason class for ops / tests.
    #[must_use]
    pub const fn reason_class(&self) -> &'static str {
        match self {
            Self::UnsupportedKind(_) => "unsupported_kind",
            Self::Services => "services",
            Self::Token => "token",
            Self::RateLimited => "rate_limited",
            Self::InvalidPhone => "invalid_phone",
            Self::Delivery(_) => "delivery",
            Self::TotpUnavailable => "totp_unavailable",
            Self::TotpInvalid => "mismatch",
            Self::TotpSecret => "totp_secret",
            Self::UserMissing => "user",
        }
    }
}

/// Issues and verifies factor challenges using injected [`LeptonAuthServices`].
#[cfg(feature = "ssr")]
#[derive(Clone)]
pub struct FactorChallengeService {
    /// Used by email/phone issue paths when those features are enabled.
    #[cfg_attr(not(any(feature = "email", feature = "phone")), allow(dead_code))]
    #[cfg_attr(feature = "boson-delivery", allow(dead_code))]
    pub(crate) services: Arc<LeptonAuthServices>,
}

#[cfg(feature = "ssr")]
impl FactorChallengeService {
    /// Create a service bound to the given auth services bundle.
    #[must_use]
    pub const fn new(services: Arc<LeptonAuthServices>) -> Self {
        Self { services }
    }

    /// Issue an email OTP challenge (`email` feature). Returns the challenge id (not the code).
    #[cfg(feature = "email")]
    pub async fn issue_email_otp(
        &self,
        valence: &Valence,
        user: RecordId,
        target: &str,
        email_flow: lepton_smtp::VerificationEmailFlow,
    ) -> Result<String, FactorChallengeError> {
        let result = email_otp::issue(self, valence, user, target, email_flow).await;
        #[cfg(feature = "spectra")]
        match &result {
            Ok(_) => crate::spectra_emit::verify(
                crate::spectra_emit::VerifyChannel::Email,
                crate::spectra_emit::VerifyStage::Issue,
                crate::spectra_emit::AuthOutcome::Success,
                "none",
            ),
            Err(e) => crate::spectra_emit::verify(
                crate::spectra_emit::VerifyChannel::Email,
                crate::spectra_emit::VerifyStage::Issue,
                crate::spectra_emit::AuthOutcome::Failure,
                e.reason_class(),
            ),
        }
        result
    }

    /// Issue an SMS OTP challenge (`phone` feature). Returns the challenge id (not the OTP).
    #[cfg(feature = "phone")]
    pub async fn issue_sms_otp(
        &self,
        valence: &Valence,
        user: RecordId,
        target: &str,
    ) -> Result<String, FactorChallengeError> {
        let result = phone_otp::issue(self, valence, user, target).await;
        #[cfg(feature = "spectra")]
        match &result {
            Ok(_) => crate::spectra_emit::verify(
                crate::spectra_emit::VerifyChannel::Phone,
                crate::spectra_emit::VerifyStage::Issue,
                crate::spectra_emit::AuthOutcome::Success,
                "none",
            ),
            Err(e) => crate::spectra_emit::verify(
                crate::spectra_emit::VerifyChannel::Phone,
                crate::spectra_emit::VerifyStage::Issue,
                crate::spectra_emit::AuthOutcome::Failure,
                e.reason_class(),
            ),
        }
        result
    }

    /// Dispatch issue by [`FactorChallengeKind`]. Disabled-feature kinds return
    /// [`FactorChallengeError::UnsupportedKind`]. Totp cannot be issued this way.
    #[allow(clippy::unused_async)] // awaits only when email / phone features are enabled
    pub async fn issue(
        &self,
        kind: FactorChallengeKind,
        valence: &Valence,
        user: RecordId,
        target: &str,
        #[cfg(feature = "email")] email_flow: lepton_smtp::VerificationEmailFlow,
    ) -> Result<String, FactorChallengeError> {
        match kind {
            FactorChallengeKind::EmailOtp => {
                #[cfg(feature = "email")]
                {
                    self.issue_email_otp(valence, user, target, email_flow)
                        .await
                }
                #[cfg(not(feature = "email"))]
                {
                    let _ = (valence, user, target);
                    Err(FactorChallengeError::UnsupportedKind(kind))
                }
            }
            FactorChallengeKind::SmsOtp => {
                #[cfg(feature = "phone")]
                {
                    #[cfg(feature = "email")]
                    let _ = email_flow;
                    self.issue_sms_otp(valence, user, target).await
                }
                #[cfg(not(feature = "phone"))]
                {
                    let _ = (valence, user, target);
                    #[cfg(feature = "email")]
                    let _ = email_flow;
                    Err(FactorChallengeError::UnsupportedKind(kind))
                }
            }
            FactorChallengeKind::Totp => {
                let _ = (valence, user, target);
                #[cfg(feature = "email")]
                let _ = email_flow;
                Err(FactorChallengeError::UnsupportedKind(kind))
            }
        }
    }

    /// Consume `user`'s emailed code (`email` feature). Returns `Ok(false)` for a wrong, used
    /// or expired code and [`FactorChallengeError::RateLimited`] once the attempt budget is spent.
    #[cfg(feature = "email")]
    pub async fn verify_email_otp(
        &self,
        user: &RecordId,
        otp_code: &str,
        valence: &Valence,
    ) -> Result<bool, FactorChallengeError> {
        let result = email_otp::verify(user, otp_code, valence).await;
        #[cfg(feature = "spectra")]
        match &result {
            Ok(true) => crate::spectra_emit::verify(
                crate::spectra_emit::VerifyChannel::Email,
                crate::spectra_emit::VerifyStage::Consume,
                crate::spectra_emit::AuthOutcome::Success,
                "none",
            ),
            Ok(false) => crate::spectra_emit::verify(
                crate::spectra_emit::VerifyChannel::Email,
                crate::spectra_emit::VerifyStage::Consume,
                crate::spectra_emit::AuthOutcome::Failure,
                "token",
            ),
            Err(e) => crate::spectra_emit::verify(
                crate::spectra_emit::VerifyChannel::Email,
                crate::spectra_emit::VerifyStage::Consume,
                crate::spectra_emit::AuthOutcome::Failure,
                e.reason_class(),
            ),
        }
        result
    }

    /// Consume an SMS OTP, set `User.phone` / `phone_verified`, publish Photon (`phone`).
    #[cfg(feature = "phone")]
    pub async fn verify_sms_otp(
        &self,
        challenge_id: &str,
        otp_code: &str,
        valence: &Valence,
    ) -> Result<bool, FactorChallengeError> {
        let result = phone_otp::verify(challenge_id, otp_code, valence).await;
        #[cfg(feature = "spectra")]
        match &result {
            Ok(true) => crate::spectra_emit::verify(
                crate::spectra_emit::VerifyChannel::Phone,
                crate::spectra_emit::VerifyStage::Consume,
                crate::spectra_emit::AuthOutcome::Success,
                "none",
            ),
            Ok(false) => crate::spectra_emit::verify(
                crate::spectra_emit::VerifyChannel::Phone,
                crate::spectra_emit::VerifyStage::Consume,
                crate::spectra_emit::AuthOutcome::Failure,
                "mismatch",
            ),
            Err(e) => crate::spectra_emit::verify(
                crate::spectra_emit::VerifyChannel::Phone,
                crate::spectra_emit::VerifyStage::Consume,
                crate::spectra_emit::AuthOutcome::Failure,
                e.reason_class(),
            ),
        }
        result
    }

    /// Verify a TOTP code against the user's enabled factor, then publish Photon (`totp`).
    #[cfg(feature = "totp")]
    pub async fn verify_totp_code(
        &self,
        valence: &Valence,
        user: &RecordId,
        code: &str,
    ) -> Result<(), FactorChallengeError> {
        let result = totp::verify_for_user(valence, user, code).await;
        #[cfg(feature = "spectra")]
        match &result {
            Ok(()) => {
                crate::spectra_emit::verify(
                    crate::spectra_emit::VerifyChannel::Totp,
                    crate::spectra_emit::VerifyStage::Consume,
                    crate::spectra_emit::AuthOutcome::Success,
                    "none",
                );
                crate::spectra_emit::totp(
                    crate::spectra_emit::TotpOperation::Verify,
                    crate::spectra_emit::AuthOutcome::Success,
                    "none",
                );
                crate::spectra_emit::step_up(
                    crate::spectra_emit::StepUpPath::Totp,
                    crate::spectra_emit::AuthOutcome::Success,
                    "none",
                );
            }
            Err(e) => {
                crate::spectra_emit::verify(
                    crate::spectra_emit::VerifyChannel::Totp,
                    crate::spectra_emit::VerifyStage::Consume,
                    crate::spectra_emit::AuthOutcome::Failure,
                    e.reason_class(),
                );
                crate::spectra_emit::totp(
                    crate::spectra_emit::TotpOperation::Verify,
                    crate::spectra_emit::AuthOutcome::Failure,
                    e.reason_class(),
                );
                crate::spectra_emit::step_up(
                    crate::spectra_emit::StepUpPath::Totp,
                    crate::spectra_emit::AuthOutcome::Failure,
                    e.reason_class(),
                );
            }
        }
        result
    }

    /// Consume a one-time TOTP recovery code, then publish Photon (`totp`).
    ///
    /// # Errors
    ///
    /// [`FactorChallengeError::TotpInvalid`] when the code is wrong or already used;
    /// store failures map to [`FactorChallengeError::Token`].
    #[cfg(feature = "totp")]
    pub async fn consume_totp_recovery_code(
        &self,
        valence: &Valence,
        user: &RecordId,
        code: &str,
    ) -> Result<(), FactorChallengeError> {
        let result = totp::consume_recovery_for_user(valence, user, code).await;
        #[cfg(feature = "spectra")]
        match &result {
            Ok(()) => {
                crate::spectra_emit::verify(
                    crate::spectra_emit::VerifyChannel::Totp,
                    crate::spectra_emit::VerifyStage::Consume,
                    crate::spectra_emit::AuthOutcome::Success,
                    "none",
                );
            }
            Err(e) => {
                crate::spectra_emit::verify(
                    crate::spectra_emit::VerifyChannel::Totp,
                    crate::spectra_emit::VerifyStage::Consume,
                    crate::spectra_emit::AuthOutcome::Failure,
                    e.reason_class(),
                );
            }
        }
        result
    }

    /// Verify TOTP, or accept a still-trusted bound `AuthDevice` as MFA skip for step-up.
    ///
    /// When `bound_device_id` names a non-revoked trusted device owned by `user`, returns `Ok`
    /// without checking `totp_code`. Otherwise requires a valid TOTP code (`Some`).
    ///
    /// # Errors
    ///
    /// Same as [`Self::verify_totp_code`] when a code is required; device store failures.
    #[cfg(feature = "totp")]
    pub async fn verify_totp_or_bound_device(
        &self,
        valence: &Valence,
        user: &RecordId,
        bound_device_id: Option<&str>,
        totp_code: Option<&str>,
    ) -> Result<(), FactorChallengeError> {
        if let Some(device_id) = bound_device_id {
            match crate::devices::touch_auth_device(valence, user, device_id).await {
                Ok(()) => {
                    tracing::info!(
                        operation = "factor.totp_or_bound",
                        path = "bound_device",
                        "step-up skipped via bound device"
                    );
                    #[cfg(feature = "spectra")]
                    crate::spectra_emit::step_up(
                        crate::spectra_emit::StepUpPath::BoundDevice,
                        crate::spectra_emit::AuthOutcome::Success,
                        "none",
                    );
                    return Ok(());
                }
                Err(
                    crate::devices::DeviceError::Revoked
                    | crate::devices::DeviceError::Pending
                    | crate::devices::DeviceError::DeviceMissing,
                ) => {
                    tracing::info!(
                        operation = "factor.totp_or_bound",
                        path = "reject",
                        "bound device not usable; requiring totp"
                    );
                }
                Err(_) => {
                    #[cfg(feature = "spectra")]
                    crate::spectra_emit::step_up(
                        crate::spectra_emit::StepUpPath::Reject,
                        crate::spectra_emit::AuthOutcome::Failure,
                        "token",
                    );
                    return Err(FactorChallengeError::Token);
                }
            }
        }
        let Some(code) = totp_code else {
            #[cfg(feature = "spectra")]
            crate::spectra_emit::step_up(
                crate::spectra_emit::StepUpPath::Reject,
                crate::spectra_emit::AuthOutcome::Failure,
                "mismatch",
            );
            return Err(FactorChallengeError::TotpInvalid);
        };
        tracing::info!(
            operation = "factor.totp_or_bound",
            path = "totp",
            "step-up verifying totp"
        );
        let result = self.verify_totp_code(valence, user, code).await;
        // `verify_totp_code` already records `lepton_step_up` for the TOTP path.
        result
    }
}

/// Strip `table:` prefix from a [`RecordId`] string (TOTP factor lookups).
#[cfg(all(feature = "ssr", feature = "totp"))]
pub(crate) fn bare_id(id: &RecordId) -> String {
    let s = id.to_string();
    s.split_once(':')
        .map(|(_, rest)| rest.to_string())
        .unwrap_or(s)
}
