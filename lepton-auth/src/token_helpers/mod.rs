//! One-time token (email verification, phone verification, password reset) issuance and lifecycle.
//!
//! # Concern → API
//!
//! | Concern | API |
//! |---------|-----|
//! | Lifecycle gate | `ensure_token_lifecycle_valid` |
//! | Secret check (also password PHC verify) | `verify_token_secret` |
//! | Issue email / reset | `issue_email_verification_token` |
//! | Issue / consume phone (`phone`) | `issue_phone_verification_token`, `try_consume_phone_verification_token` |
//! | Consume (unique-marker winner) | `try_consume_email_verification_token`, `try_consume_password_reset_token` |
//!
//! Consume uses an **optimistic unique-marker** pattern (not a DB `UPDATE … WHERE` CAS):
//! after secret/lifecycle checks, the caller writes a unique `$consumed$…` marker into
//! `token_hash`, reloads, and succeeds only when the stored hash still equals that marker.
//! Concurrent losers observe a different marker and return failure / `None`.
//!
//! # Examples
//!
//! Verify a PHC hash (password re-check or token secret):
//!
//! ```rust,ignore
//! use lepton_auth::token_helpers::verify_token_secret;
//!
//! verify_token_secret(presented_password, &stored_phc_hash)?;
//! ```
//!
//! Runnable: `examples/password_and_token`. Issue/consume against Valence needs an SSR host
//! (see [`crate::factor`]).

#[cfg(feature = "ssr")]
use chrono::{Duration, Utc};
#[cfg(feature = "ssr")]
use lepton_host_adapter::generated::{EmailVerificationToken, OneTimeTokenLifecycleFields};
#[cfg(feature = "ssr")]
use leptos::prelude::ServerFnError;
#[cfg(feature = "ssr")]
use thiserror::Error;
#[cfg(feature = "ssr")]
use valence::Model;
#[cfg(feature = "ssr")]
use valence::RecordId;
#[cfg(feature = "ssr")]
use valence::Valence;

#[cfg(feature = "ssr")]
use crate::security::random_token_part;

#[cfg(all(feature = "ssr", feature = "phone"))]
mod phone;
#[cfg(all(feature = "ssr", feature = "phone"))]
pub use phone::{
    generate_phone_otp_code, issue_phone_verification_token, try_consume_phone_verification_token,
    IssuedPhoneChallenge, PHONE_OTP_DIGIT_LEN,
};

/// Why a one-time token failed lifecycle or secret checks.
#[cfg(feature = "ssr")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TokenLifecycleError {
    /// The token has already been consumed.
    #[error("Token has already been used")]
    Used,
    /// The token's expiry has passed.
    #[error("Token has expired")]
    Expired,
    /// The token secret did not match the stored hash.
    #[error("Invalid token")]
    Invalid,
}

#[cfg(feature = "ssr")]
impl TokenLifecycleError {
    /// Stable human-readable message (same as [`Display`](std::fmt::Display)).
    #[must_use]
    pub const fn message(&self) -> &'static str {
        match self {
            Self::Used => "Token has already been used",
            Self::Expired => "Token has expired",
            Self::Invalid => "Invalid token",
        }
    }

    /// Ops / mapping token for client-opaque boundaries.
    #[must_use]
    pub const fn reason_class(self) -> &'static str {
        match self {
            Self::Used => "used",
            Self::Expired => "expired",
            Self::Invalid => "invalid",
        }
    }
}

/// Opaque persistence failure for public / server-fn boundaries (no inner transport text).
#[cfg(feature = "ssr")]
pub(super) fn token_store_error(reason_class: &str) -> ServerFnError {
    ServerFnError::new(format!(
        "reason_class={reason_class}: token operation failed"
    ))
}

/// Create a unique consume marker written into `token_hash` after a successful consume.
#[cfg(feature = "ssr")]
#[must_use]
pub fn new_consume_marker() -> String {
    format!("$consumed${}", random_token_part(16))
}

/// Whether this caller won the unique-marker race after writing `consume_marker`.
#[cfg(feature = "ssr")]
#[must_use]
pub fn consume_marker_won(latest_token_hash: &str, consume_marker: &str) -> bool {
    latest_token_hash == consume_marker
}

/// Check that a one-time token record has not been used and has not expired.
#[cfg(feature = "ssr")]
pub fn ensure_token_lifecycle_valid(
    record: &impl OneTimeTokenLifecycleFields,
) -> Result<(), TokenLifecycleError> {
    if record.used_at().is_some() {
        return Err(TokenLifecycleError::Used);
    }
    if *record.expires_at() < Utc::now() {
        return Err(TokenLifecycleError::Expired);
    }
    Ok(())
}

/// Verify a plaintext one-time secret against its stored Argon2 hash.
#[cfg(feature = "ssr")]
pub fn verify_token_secret(secret: &str, token_hash: &str) -> Result<(), TokenLifecycleError> {
    use argon2::{password_hash::PasswordHash, PasswordVerifier};

    let parsed_hash = PasswordHash::new(token_hash).map_err(|_| TokenLifecycleError::Invalid)?;
    if argon2::Argon2::default()
        .verify_password(secret.as_bytes(), &parsed_hash)
        .is_err()
    {
        return Err(TokenLifecycleError::Invalid);
    }
    Ok(())
}

/// Shared pre-write validation for consume paths.
#[cfg(feature = "ssr")]
pub(super) fn ready_to_consume(
    record: &impl OneTimeTokenLifecycleFields,
    plaintext_secret: &str,
) -> Result<(), TokenLifecycleError> {
    ensure_token_lifecycle_valid(record)?;
    verify_token_secret(plaintext_secret, record.token_hash())?;
    Ok(())
}

/// Validate and consume an email verification token (unique-marker winner).
///
/// Returns `true` only when this caller wins the marker race after a valid secret match.
/// The email link secret **is** the record id (`token_id`).
#[cfg(feature = "ssr")]
pub async fn try_consume_email_verification_token(
    token_id: &str,
    valence: &Valence,
) -> Result<bool, ServerFnError> {
    let token = EmailVerificationToken::get(token_id, valence, valence::use_!(r"In **token_helpers**, we **load Email Verification Token** so the application can decide what to do next in this workflow. The result is used by **token_helpers** logic—not necessarily displayed on a page unless that feature’s UI shows it."))
        .await
        .map_err(|_| token_store_error("load"))?;
    let Some(token) = token else {
        return Ok(false);
    };

    if ready_to_consume(&token, token_id).is_err() {
        return Ok(false);
    }

    let consume_marker = new_consume_marker();
    token
        .get_mutable(valence, valence::use_!(r"In **token helpers**, we **update this data** so later steps see the latest values for this workflow. Callers allowed for **token helpers** use the updated data; this is not a public export of unrelated fields."))
        .set_used_at(Utc::now())
        .map_err(|_| token_store_error("mark_used"))?
        .set_token_hash(consume_marker.clone())
        .map_err(|_| token_store_error("mark_hash"))?
        .commit()
        .await
        .map_err(|_| token_store_error("persist"))?;

    let latest = EmailVerificationToken::get(token_id, valence, valence::use_!(r"In **token_helpers**, we **load Email Verification Token** so the application can decide what to do next in this workflow. The result is used by **token_helpers** logic—not necessarily displayed on a page unless that feature’s UI shows it."))
        .await
        .map_err(|_| token_store_error("reload"))?;
    let Some(latest) = latest else {
        return Ok(false);
    };
    Ok(consume_marker_won(latest.token_hash(), &consume_marker))
}

/// Validate, then unique-marker-consume a password reset token before any password write.
///
/// Returns the pre-consume record when this caller wins; `Ok(None)` when missing, invalid,
/// expired, already used, or lost a concurrent consume.
#[cfg(feature = "ssr")]
pub async fn try_consume_password_reset_token(
    token_id: &str,
    plaintext_token: &str,
    valence: &Valence,
) -> Result<Option<lepton_host_adapter::generated::PasswordResetToken>, ServerFnError> {
    use lepton_host_adapter::generated::PasswordResetToken;

    let token = PasswordResetToken::get(token_id, valence, valence::use_!(r"In **token_helpers**, we **load Password Reset Token** so the application can decide what to do next in this workflow. The result is used by **token_helpers** logic—not necessarily displayed on a page unless that feature’s UI shows it."))
        .await
        .map_err(|_| token_store_error("load"))?;
    let Some(token) = token else {
        return Ok(None);
    };

    if ready_to_consume(&token, plaintext_token).is_err() {
        return Ok(None);
    }

    let consume_marker = new_consume_marker();
    token
        .get_mutable(valence, valence::use_!(r"In **token helpers**, we **update this data** so later steps see the latest values for this workflow. Callers allowed for **token helpers** use the updated data; this is not a public export of unrelated fields."))
        .set_used_at(Utc::now())
        .map_err(|_| token_store_error("mark_used"))?
        .set_token_hash(consume_marker.clone())
        .map_err(|_| token_store_error("mark_hash"))?
        .commit()
        .await
        .map_err(|_| token_store_error("persist"))?;

    let latest = PasswordResetToken::get(token_id, valence, valence::use_!(r"In **token_helpers**, we **load Password Reset Token** so the application can decide what to do next in this workflow. The result is used by **token_helpers** logic—not necessarily displayed on a page unless that feature’s UI shows it."))
        .await
        .map_err(|_| token_store_error("reload"))?;
    let Some(latest) = latest else {
        return Ok(None);
    };
    if !consume_marker_won(latest.token_hash(), &consume_marker) {
        return Ok(None);
    }

    Ok(Some(token))
}

/// Generate, hash, and persist a fresh email verification token for `user_email` (30 min TTL).
///
/// Returns the plaintext token id (also the URL fragment secret).
#[cfg(feature = "ssr")]
pub async fn issue_email_verification_token(
    valence: &Valence,
    user: RecordId,
    user_email: RecordId,
) -> Result<String, ServerFnError> {
    let token_id = random_token_part(12);
    let token_hash = lepton_host_adapter::auth::hash_password(&token_id)
        .map_err(|_| token_store_error("hash"))?;

    let token = EmailVerificationToken::new(
        user,
        user_email,
        token_hash,
        Utc::now() + Duration::minutes(30),
        None,
        Utc::now(),
    )
    .map_err(|_| token_store_error("build"))?;

    EmailVerificationToken::upsert(&token_id, token, valence, valence::use_!(r"When **token_helpers** needs to persist work, we **save Email Verification Token** so the next step in that feature can continue with the latest values. People and services allowed for **token_helpers** use this data for that workflow—not as a general export of unrelated personal fields."))
        .await
        .map_err(|_| token_store_error("persist"))?;

    Ok(token_id)
}

#[cfg(all(test, feature = "ssr"))]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use lepton_identity::auth::hash_password;

    #[test]
    fn token_lifecycle_error_messages() {
        assert_eq!(
            TokenLifecycleError::Used.message(),
            "Token has already been used"
        );
        assert_eq!(TokenLifecycleError::Expired.message(), "Token has expired");
        assert_eq!(TokenLifecycleError::Invalid.message(), "Invalid token");
        assert_eq!(
            TokenLifecycleError::Used.to_string(),
            "Token has already been used"
        );
        assert_eq!(TokenLifecycleError::Used.reason_class(), "used");
    }

    #[test]
    fn verify_token_secret_accepts_matching_hash() {
        let token = "one-time-secret";
        let hash = hash_password(token).expect("hash");
        assert!(verify_token_secret(token, &hash).is_ok());
    }

    #[test]
    fn verify_token_secret_rejects_mismatch_and_garbage() {
        let hash = hash_password("one-time-secret").expect("hash");
        assert!(matches!(
            verify_token_secret("wrong", &hash),
            Err(TokenLifecycleError::Invalid)
        ));
        assert!(matches!(
            verify_token_secret("anything", "not-a-phc-hash"),
            Err(TokenLifecycleError::Invalid)
        ));
    }

    #[test]
    fn consume_cas_race_loser_sad() {
        let winner = new_consume_marker();
        let loser = new_consume_marker();
        assert!(consume_marker_won(&winner, &winner));
        assert!(!consume_marker_won(&winner, &loser));
    }

    #[test]
    fn issue_and_consume_one_time_token_happy_path() {
        // Pure secret/hash + marker contract (Valence-backed path covered in integ tests).
        let secret = "issue-consume-secret";
        let hash = hash_password(secret).expect("hash");
        assert!(verify_token_secret(secret, &hash).is_ok());
        let marker = new_consume_marker();
        assert!(consume_marker_won(&marker, &marker));
    }

    #[test]
    fn consume_bad_secret_sad() {
        let hash = hash_password("correct").expect("hash");
        assert!(matches!(
            verify_token_secret("wrong", &hash),
            Err(TokenLifecycleError::Invalid)
        ));
    }
}
