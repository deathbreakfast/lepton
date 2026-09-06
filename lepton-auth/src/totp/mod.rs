//! TOTP enroll / disable / recovery-code helpers (`totp` feature).
//!
//! Verify remains on [`crate::factor::FactorChallengeService`].
//! Host Account Settings enroll UI calls [`crate::actions::totp`] server functions.
//!
//! # Examples
//!
//! ```rust,ignore
//! use lepton_auth::factor::FactorChallengeService;
//! use lepton_auth::totp::{
//!     begin_totp_enroll, confirm_totp_enroll, consume_totp_recovery_code, disable_totp,
//!     regenerate_totp_recovery_codes,
//! };
//!
//! async fn enroll_then_disable_totp(
//!     v: &valence::Valence,
//!     user: valence::RecordId,
//!     svc: &FactorChallengeService,
//!     code: &str,
//! ) -> Result<(), Box<dyn std::error::Error>> {
//!     let pending = begin_totp_enroll(v, &user, "you@example.com", "Unified Field").await?;
//!     // Host shows `pending.otpauth_uri` as a QR; `code` is from the authenticator app.
//!     confirm_totp_enroll(v, &user, &pending.factor_id, code).await?;
//!     let codes = regenerate_totp_recovery_codes(v, &user).await?;
//!     consume_totp_recovery_code(v, &user, &codes[0]).await?;
//!     svc.verify_totp_code(v, &user, code).await?;
//!     disable_totp(v, &user).await?;
//!     Ok(())
//! }
//! ```

#[cfg(all(feature = "ssr", feature = "totp"))]
mod api;
#[cfg(all(feature = "ssr", feature = "totp"))]
mod error;
#[cfg(all(feature = "ssr", feature = "totp"))]
mod qr;
#[cfg(all(feature = "ssr", feature = "totp"))]
pub(crate) mod seal;

#[cfg(all(feature = "ssr", feature = "totp"))]
pub use api::{
    begin_totp_enroll, confirm_totp_enroll, consume_totp_recovery_code, disable_totp,
    regenerate_totp_recovery_codes, PendingTotpEnroll,
};
#[cfg(all(feature = "ssr", feature = "totp"))]
pub use error::TotpEnrollError;
#[cfg(all(feature = "ssr", feature = "totp"))]
pub use qr::{format_manual_secret, manual_secret_from_otpauth_uri, qr_svg_for_otpauth};

#[cfg(all(feature = "ssr", feature = "totp"))]
pub use crate::factor::verify_totp_against_sealed;
