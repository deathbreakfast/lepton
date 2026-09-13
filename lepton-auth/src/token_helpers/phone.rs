//! Phone verification token issue / consume (`phone` feature).

use chrono::{Duration, Utc};
use lepton_host_adapter::generated::PhoneVerificationToken;
use leptos::prelude::ServerFnError;
use rand_core::RngCore;
use valence::{Model, RecordId, Valence};

use super::{consume_marker_won, new_consume_marker, ready_to_consume, token_store_error};
use crate::security::random_token_part;

/// Digit length of SMS OTPs (fits Twilio Verify `CustomCode` max of 10).
pub const PHONE_OTP_DIGIT_LEN: usize = 6;

/// Issued phone verification challenge: record id (Photon / status key) + SMS OTP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedPhoneChallenge {
    /// Valence record id / challenge id (not the SMS OTP).
    pub challenge_id: String,
    /// Short numeric OTP sent via SMS; hashed at rest in `token_hash`.
    pub otp_code: String,
}

/// Cryptographically random [`PHONE_OTP_DIGIT_LEN`]-digit OTP (zero-padded).
#[must_use]
pub fn generate_phone_otp_code() -> String {
    let mut bytes = [0u8; 4];
    rand_core::OsRng.fill_bytes(&mut bytes);
    let n = u32::from_le_bytes(bytes) % 1_000_000;
    format!("{n:0PHONE_OTP_DIGIT_LEN$}")
}

/// Validate and consume a phone verification token using the SMS OTP (not the record id).
///
/// Returns the pre-consume record when this caller wins so callers can update the contact.
pub async fn try_consume_phone_verification_token(
    challenge_id: &str,
    otp_code: &str,
    valence: &Valence,
) -> Result<Option<PhoneVerificationToken>, ServerFnError> {
    let token = PhoneVerificationToken::get_used(challenge_id, valence, valence::use_!(r#"In **token_helpers**, we **load Phone Verification Token** so the application can decide what to do next in this workflow. The result is used by **token_helpers** logic—not necessarily displayed on a page unless that feature’s UI shows it."#))
        .await
        .map_err(|_| token_store_error("load"))?;
    let Some(token) = token else {
        return Ok(None);
    };

    if ready_to_consume(&token, otp_code.trim()).is_err() {
        return Ok(None);
    }

    let consume_marker = new_consume_marker();
    token
        .get_mutable_used(valence, valence::use_!(r#"In **token helpers**, we **update this data** so later steps see the latest values for this workflow. Callers allowed for **token helpers** use the updated data; this is not a public export of unrelated fields."#))
        .set_used_at(Utc::now())
        .map_err(|_| token_store_error("mark_used"))?
        .set_token_hash(consume_marker.clone())
        .map_err(|_| token_store_error("mark_hash"))?
        .commit()
        .await
        .map_err(|_| token_store_error("persist"))?;

    let latest = PhoneVerificationToken::get_used(challenge_id, valence, valence::use_!(r#"In **token_helpers**, we **load Phone Verification Token** so the application can decide what to do next in this workflow. The result is used by **token_helpers** logic—not necessarily displayed on a page unless that feature’s UI shows it."#))
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

/// Generate a phone challenge for `user_phone`: random record id + short OTP (hashed at rest).
///
/// The SMS body / Verify `CustomCode` must carry [`IssuedPhoneChallenge::otp_code`] only —
/// never the record id (`challenge_id`).
pub async fn issue_phone_verification_token(
    valence: &Valence,
    user: RecordId,
    user_phone: RecordId,
) -> Result<IssuedPhoneChallenge, ServerFnError> {
    let challenge_id = random_token_part(12);
    // 6 digits — distinct from challenge_id so SMS intercept ≠ DB primary key.
    let otp_code = generate_phone_otp_code();
    let token_hash = lepton_host_adapter::auth::hash_password(&otp_code)
        .map_err(|_| token_store_error("hash"))?;

    let token = PhoneVerificationToken::new(
        user,
        user_phone,
        token_hash,
        Utc::now() + Duration::minutes(30),
        None,
        Utc::now(),
    )
    .map_err(|_| token_store_error("build"))?;

    PhoneVerificationToken::upsert_used(&challenge_id, token, valence, valence::use_!(r#"When **token_helpers** needs to persist work, we **save Phone Verification Token** so the next step in that feature can continue with the latest values. People and services allowed for **token_helpers** use this data for that workflow—not as a general export of unrelated personal fields."#))
        .await
        .map_err(|_| token_store_error("persist"))?;

    Ok(IssuedPhoneChallenge {
        challenge_id,
        otp_code,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::{generate_phone_otp_code, PHONE_OTP_DIGIT_LEN};

    #[test]
    fn phone_otp_is_six_digits_happy() {
        for _ in 0..32 {
            let code = generate_phone_otp_code();
            assert_eq!(code.len(), PHONE_OTP_DIGIT_LEN);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
        }
    }
}
