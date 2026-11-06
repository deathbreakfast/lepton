//! One-time token (email verification, phone verification, password reset) issuance and lifecycle.
//!
//! # Concern → API
//!
//! | Concern | API |
//! |---------|-----|
//! | Lifecycle gate | `ensure_token_lifecycle_valid` |
//! | Secret check (also password PHC verify) | `verify_token_secret` |
//! | Issue email code (6 digits, one live code per user) | `issue_email_verification_token` |
//! | Resend cooldown | `email_resend_wait_secs`, `resend_wait_secs` |
//! | Issue / consume phone (`phone`) | `issue_phone_verification_token`, `try_consume_phone_verification_token` |
//! | Consume email code (attempt lockout) | `consume_email_verification_token` |
//! | Consume reset token (unique-marker winner) | `try_consume_password_reset_token` |
//!
//! Consume uses an **optimistic unique-marker** pattern (not a DB `UPDATE … WHERE` CAS):
//! after secret/lifecycle checks, the caller writes a unique `$consumed$…` marker into
//! `token_hash`, reloads, and succeeds only when the stored hash still equals that marker.
//! Concurrent losers observe a different marker and return failure / `None`.
//!
//! Email codes add an attempt budget: five wrong codes lock the token for five minutes, and a
//! new code does not clear a lockout that is still running.
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
use crate::attempt_throttle::{is_locked, record_failure};
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
    /// Too many wrong codes; the token is locked until the lockout ends.
    #[error("Too many attempts; try again later")]
    Locked,
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
            Self::Locked => "Too many attempts; try again later",
        }
    }

    /// Ops / mapping token for client-opaque boundaries.
    #[must_use]
    pub const fn reason_class(self) -> &'static str {
        match self {
            Self::Used => "used",
            Self::Expired => "expired",
            Self::Invalid => "invalid",
            Self::Locked => "rate_limited",
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

/// Validate and consume the signed-in user's emailed verification code (unique-marker winner).
///
/// The record is keyed by `user`, so the 6-digit `otp_code` is checked against that user's
/// single live token. A wrong code counts toward the attempt budget
/// (five misses); the miss that exhausts it locks the token until the lockout
/// ends, and a locked token rejects even the right code.
///
/// Returns the pre-consume record when this caller wins. The inner error says why the code was
/// refused; the outer one is a persistence failure.
#[cfg(feature = "ssr")]
pub async fn consume_email_verification_token(
    valence: &Valence,
    user: &RecordId,
    otp_code: &str,
) -> Result<Result<EmailVerificationToken, TokenLifecycleError>, ServerFnError> {
    let token_id = email_verification_challenge_id(user);
    let token = EmailVerificationToken::get(&token_id, valence, valence::use_!(r"When you **enter an emailed verification code**, we **load your pending code record** to check the code, its expiry and any lockout. Only the signed-in user's own code is checked, and nothing from the record is shown back."))
        .await
        .map_err(|_| token_store_error("load"))?;
    let Some(token) = token else {
        return Ok(Err(TokenLifecycleError::Invalid));
    };

    if let Err(err) = ensure_token_lifecycle_valid(&token) {
        return Ok(Err(err));
    }
    let now = Utc::now();
    if is_locked(token.locked_until(), now) {
        return Ok(Err(TokenLifecycleError::Locked));
    }
    if verify_token_secret(otp_code.trim(), token.token_hash()).is_err() {
        let (failed, locked_until) =
            record_failure(token.failed_attempts().copied().unwrap_or(0), now);
        let mut mutable = token
            .get_mutable(valence, valence::use_!(r"When an **emailed verification code is wrong**, we **record the failed attempt** on that code and lock it after too many misses, so repeated guesses get rate-limited."))
            .set_failed_attempts(failed)
            .map_err(|_| token_store_error("mark_failed"))?;
        mutable = match locked_until {
            Some(until) => mutable
                .set_locked_until(until)
                .map_err(|_| token_store_error("mark_locked"))?,
            None => mutable.clear_locked_until(),
        };
        mutable
            .commit()
            .await
            .map_err(|_| token_store_error("persist"))?;
        return Ok(Err(if locked_until.is_some() {
            TokenLifecycleError::Locked
        } else {
            TokenLifecycleError::Invalid
        }));
    }

    let consume_marker = new_consume_marker();
    token
        .get_mutable(valence, valence::use_!(r"In **token helpers**, we **update this data** so later steps see the latest values for this workflow. Callers allowed for **token helpers** use the updated data; this is not a public export of unrelated fields."))
        .set_used_at(now)
        .map_err(|_| token_store_error("mark_used"))?
        .set_token_hash(consume_marker.clone())
        .map_err(|_| token_store_error("mark_hash"))?
        .commit()
        .await
        .map_err(|_| token_store_error("persist"))?;

    let latest = EmailVerificationToken::get(&token_id, valence, valence::use_!(r"In **token_helpers**, we **load Email Verification Token** so the application can decide what to do next in this workflow. The result is used by **token_helpers** logic—not necessarily displayed on a page unless that feature’s UI shows it."))
        .await
        .map_err(|_| token_store_error("reload"))?;
    let Some(latest) = latest else {
        return Ok(Err(TokenLifecycleError::Invalid));
    };
    if !consume_marker_won(latest.token_hash(), &consume_marker) {
        return Ok(Err(TokenLifecycleError::Used));
    }
    Ok(Ok(token))
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

/// Seconds a user must wait between emailed verification codes.
#[cfg(feature = "ssr")]
pub const EMAIL_RESEND_COOLDOWN_SECS: i64 = 60;

/// Digits in an emailed verification code.
#[cfg(feature = "ssr")]
pub const EMAIL_OTP_DIGIT_LEN: usize = 6;

/// Record id of a user's email verification token, also its challenge id.
///
/// It keys [`crate::verification::verification_status`] and the completed event. It is the bare
/// user id, so each user has one live code and issuing a new one replaces the old. The id is
/// public; the code is the secret.
#[cfg(feature = "ssr")]
#[must_use]
pub fn email_verification_challenge_id(user: &RecordId) -> String {
    valence::extract_id_from_record(user).unwrap_or_else(|_| user.id().to_string())
}

/// Cryptographically random [`EMAIL_OTP_DIGIT_LEN`]-digit code (zero-padded).
#[cfg(feature = "ssr")]
#[must_use]
pub fn generate_email_otp_code() -> String {
    random_six_digit_code()
}

/// Zero-padded 6-digit code from the OS RNG (shared by the email and phone OTPs).
#[cfg(feature = "ssr")]
fn random_six_digit_code() -> String {
    use rand_core::RngCore;

    let mut bytes = [0u8; 4];
    rand_core::OsRng.fill_bytes(&mut bytes);
    let n = u32::from_le_bytes(bytes) % 1_000_000;
    format!("{n:06}")
}

/// Seconds left before another code may be sent, or `None` when sending is allowed.
#[cfg(feature = "ssr")]
#[must_use]
pub fn resend_wait_secs(
    last_issued_at: chrono::DateTime<Utc>,
    now: chrono::DateTime<Utc>,
) -> Option<i64> {
    let ready_at = last_issued_at + Duration::seconds(EMAIL_RESEND_COOLDOWN_SECS);
    (ready_at > now).then(|| (ready_at - now).num_seconds().max(1))
}

/// Seconds `user` must still wait before another verification email, or `None` when a new
/// code may be issued (no token yet, or the last one is older than the cooldown).
#[cfg(feature = "ssr")]
pub async fn email_resend_wait_secs(
    valence: &Valence,
    user: &RecordId,
) -> Result<Option<i64>, ServerFnError> {
    let token = EmailVerificationToken::get(&email_verification_challenge_id(user), valence, valence::use_!(r"When you **ask for another verification email**, we **load when your last code was issued** to decide whether the 60-second wait is over. Only the issue time is read, and it is not shown to anyone."))
        .await
        .map_err(|_| token_store_error("load"))?;
    Ok(token.and_then(|t| resend_wait_secs(*t.created_at(), Utc::now())))
}

/// Generate a fresh 6-digit code for `user_email`, hash it, and persist it (30 min TTL).
///
/// Returns the plaintext code to put in the email. It replaces any earlier code for `user`.
/// A lockout still running on the replaced code carries over, so requesting a new code does
/// not reset the attempt budget.
#[cfg(feature = "ssr")]
pub async fn issue_email_verification_token(
    valence: &Valence,
    user: RecordId,
    user_email: RecordId,
) -> Result<String, ServerFnError> {
    let token_id = email_verification_challenge_id(&user);
    let otp_code = generate_email_otp_code();
    let token_hash = lepton_host_adapter::auth::hash_password(&otp_code)
        .map_err(|_| token_store_error("hash"))?;

    let now = Utc::now();
    let previous = EmailVerificationToken::get(&token_id, valence, valence::use_!(r"When we **issue a new verification code**, we **load your previous code record** to carry over a lockout that is still running, so asking for a new code cannot reset the attempt limit."))
        .await
        .map_err(|_| token_store_error("load"))?;
    let (failed_attempts, locked_until) = previous
        .filter(|t| is_locked(t.locked_until(), now))
        .map_or((None, None), |t| {
            (t.failed_attempts().copied(), t.locked_until().copied())
        });

    let token = EmailVerificationToken::new(
        user,
        user_email,
        failed_attempts,
        locked_until,
        token_hash,
        now + Duration::minutes(30),
        None,
        now,
    )
    .map_err(|_| token_store_error("build"))?;

    EmailVerificationToken::upsert(&token_id, token, valence, valence::use_!(r"When we **issue a new verification code**, we **save its hash, expiry and any carried-over lockout** for your email address so you can confirm it later. The code itself is only sent to you by email."))
        .await
        .map_err(|_| token_store_error("persist"))?;

    Ok(otp_code)
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
    fn email_otp_is_six_digits() {
        for _ in 0..50 {
            let code = generate_email_otp_code();
            assert_eq!(code.len(), EMAIL_OTP_DIGIT_LEN);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn resend_wait_counts_down_then_clears() {
        let sent = Utc::now();
        assert_eq!(
            resend_wait_secs(sent, sent),
            Some(EMAIL_RESEND_COOLDOWN_SECS)
        );
        assert_eq!(
            resend_wait_secs(sent, sent + Duration::seconds(45)),
            Some(15)
        );
        assert_eq!(
            resend_wait_secs(sent, sent + Duration::seconds(EMAIL_RESEND_COOLDOWN_SECS)),
            None
        );
        assert_eq!(resend_wait_secs(sent, sent + Duration::hours(1)), None);
    }

    #[test]
    fn locked_error_maps_to_rate_limited() {
        assert_eq!(TokenLifecycleError::Locked.reason_class(), "rate_limited");
        assert_eq!(
            TokenLifecycleError::Locked.message(),
            "Too many attempts; try again later"
        );
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
