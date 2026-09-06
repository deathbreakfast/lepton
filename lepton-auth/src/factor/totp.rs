//! TOTP verify helpers (`totp` feature).

use lepton_host_adapter::generated::TotpFactor;
use valence::{RecordId, Valence};

use super::{bare_id, FactorChallengeError};
use crate::events::{publish_verification_completed, VerificationKind};
use crate::totp::{consume_totp_recovery_code, TotpEnrollError};

/// Verify a TOTP code against the user's enabled [`TotpFactor`], then publish Photon.
pub(super) async fn verify_for_user(
    valence: &Valence,
    user: &RecordId,
    code: &str,
) -> Result<(), FactorChallengeError> {
    let user_bare = bare_id(user);
    let factors = TotpFactor::get_from_user_id(&user_bare, valence)
        .await
        .map_err(|_| FactorChallengeError::Token)?;
    let Some(factor) = factors.into_iter().find(|f| f.enabled_at().is_some()) else {
        return Err(FactorChallengeError::TotpUnavailable);
    };
    verify_totp_against_sealed(factor.secret_sealed(), code, None)?;
    let challenge_id = factor.id().map_or_else(|| user_bare.clone(), bare_id);
    publish_verification_completed(challenge_id, VerificationKind::Totp).await;
    Ok(())
}

/// Consume a one-time recovery code, then publish Photon (`totp`).
pub(super) async fn consume_recovery_for_user(
    valence: &Valence,
    user: &RecordId,
    code: &str,
) -> Result<(), FactorChallengeError> {
    match consume_totp_recovery_code(valence, user, code).await {
        Ok(()) => {
            let challenge_id = bare_id(user);
            publish_verification_completed(challenge_id, VerificationKind::Totp).await;
            Ok(())
        }
        Err(TotpEnrollError::Mismatch) => Err(FactorChallengeError::TotpInvalid),
        Err(_) => Err(FactorChallengeError::Token),
    }
}

/// Verify `code` against a sealed (AEAD or legacy base32) TOTP secret.
///
/// **SSR / library only** — do not expose `secret_sealed` over a client-readable API.
/// When `time_secs` is `Some`, uses that Unix timestamp instead of wall clock
/// (tests / deterministic checks). Errors never echo `code` or the secret.
pub fn verify_totp_against_sealed(
    secret_sealed: &str,
    code: &str,
    time_secs: Option<u64>,
) -> Result<(), FactorChallengeError> {
    use totp_rs::{Algorithm, Secret, TOTP};

    let open = crate::totp::seal::unseal_totp_secret(secret_sealed)?;
    let secret = Secret::Encoded(open.trim().to_string())
        .to_bytes()
        .map_err(|_| FactorChallengeError::TotpSecret)?;
    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret)
        .map_err(|_| FactorChallengeError::TotpSecret)?;

    let trimmed = code.trim();
    let ok = time_secs.map_or_else(
        || totp.check_current(trimmed).unwrap_or(false),
        |t| totp.check(trimmed, t),
    );
    if ok {
        Ok(())
    } else {
        Err(FactorChallengeError::TotpInvalid)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use totp_rs::{Algorithm, Secret, TOTP};

    /// RFC 6238 test-vector secret (`12345678901234567890`) as base32.
    const FIXTURE_SECRET_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn totp_for_fixture() -> TOTP {
        let secret = Secret::Encoded(FIXTURE_SECRET_B32.to_string())
            .to_bytes()
            .expect("fixture secret bytes");
        TOTP::new(Algorithm::SHA1, 6, 1, 30, secret).expect("fixture totp")
    }

    #[test]
    fn verify_totp_happy_with_fixed_time() {
        let totp = totp_for_fixture();
        let t = 1_700_000_000_u64;
        let code = totp.generate(t);
        assert!(verify_totp_against_sealed(FIXTURE_SECRET_B32, &code, Some(t)).is_ok());
    }

    #[test]
    fn verify_totp_rejects_wrong_code_sad() {
        let err = verify_totp_against_sealed(FIXTURE_SECRET_B32, "000000", Some(1_700_000_000))
            .expect_err("wrong code");
        assert!(matches!(err, FactorChallengeError::TotpInvalid));
        let msg = err.to_string();
        assert!(!msg.contains("000000"));
        assert_eq!(err.reason_class(), "mismatch");
    }

    #[test]
    fn harness_secret_matches_otplib_style() {
        let secret = Secret::Encoded(FIXTURE_SECRET_B32.to_string())
            .to_bytes()
            .expect("harness secret");
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret).expect("totp");
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let code = totp.generate(t);
        assert!(verify_totp_against_sealed(FIXTURE_SECRET_B32, &code, Some(t)).is_ok());
        assert!(verify_totp_against_sealed(FIXTURE_SECRET_B32, &code, None).is_ok());
    }
}
