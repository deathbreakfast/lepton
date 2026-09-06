//! Step-up verify core: replay, throttle, corrupt seal, legacy migrate (TM-2).

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

use chrono::{Duration, Utc};
use lepton_auth::security::random_token_part;
use lepton_auth::step_up::{verify_code_against_factor, StepUpError};
use lepton_host_adapter::auth::hash_password;
use lepton_host_adapter::generated::{TotpFactor, User, UserStatus, UserUserType};
use support::system_valence;
use totp_rs::{Algorithm, Secret, TOTP};
use valence::{Model, RecordId};

const FIXTURE_SECRET_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

async fn seed_user(valence: &valence::Valence) -> RecordId {
    let now = Utc::now();
    let user = User::new(
        Some(UserUserType::Person),
        Some(hash_password("CorrectHorseBattery1!").expect("hash")),
        Some(UserStatus::Active),
        None,
        None,
        None,
        None,
        None,
        now,
        now,
    )
    .expect("user");
    let created = User::create(user, valence).await.expect("create user");
    created.id().cloned().expect("user id")
}

fn fixture_totp() -> TOTP {
    let secret = Secret::Encoded(FIXTURE_SECRET_B32.to_string())
        .to_bytes()
        .expect("bytes");
    TOTP::new(Algorithm::SHA1, 6, 1, 30, secret).expect("totp")
}

async fn seed_enabled_factor(
    valence: &valence::Valence,
    user: &RecordId,
    secret_sealed: String,
    last_used_step: Option<i64>,
    failed_attempts: Option<i64>,
    locked_until: Option<chrono::DateTime<Utc>>,
) -> (String, TotpFactor) {
    let now = Utc::now();
    let factor_id = random_token_part(12);
    let factor = TotpFactor::new(
        user.clone(),
        secret_sealed,
        last_used_step,
        failed_attempts,
        locked_until,
        Some(now),
        Some(now),
        now,
        now,
    )
    .expect("totp factor");
    TotpFactor::upsert(&factor_id, factor, valence)
        .await
        .expect("upsert");
    let loaded = TotpFactor::get(&factor_id, valence)
        .await
        .expect("get")
        .expect("present");
    (factor_id, loaded)
}

#[tokio::test]
async fn same_step_code_replay_denied_sad() {
    std::env::set_var("LEPTON_TOTP_ALLOW_TEST_SEAL_KEY", "1");
    let valence = system_valence("step_up_replay").await;
    let user = seed_user(&valence).await;
    let totp = fixture_totp();
    let now = Utc::now();
    let code = totp.generate(now.timestamp().cast_unsigned());

    let (factor_id, factor) =
        seed_enabled_factor(&valence, &user, FIXTURE_SECRET_B32.into(), None, None, None).await;

    verify_code_against_factor(&valence, &factor, &code, now)
        .await
        .expect("first verify in step");

    let factor_after = TotpFactor::get(&factor_id, &valence)
        .await
        .expect("get")
        .expect("present");
    let err = verify_code_against_factor(&valence, &factor_after, &code, now)
        .await
        .expect_err("same-step replay");
    assert!(matches!(err, StepUpError::StepUpInvalid));
    assert_eq!(err.reason_class(), "step_up_invalid");
    assert!(!err.to_string().contains(&code));
}

#[tokio::test]
async fn budget_exhaustion_rate_limited_sad() {
    std::env::set_var("LEPTON_TOTP_ALLOW_TEST_SEAL_KEY", "1");
    let valence = system_valence("step_up_rate_limit").await;
    let user = seed_user(&valence).await;
    let locked_until = Utc::now() + Duration::seconds(300);
    let (_id, factor) = seed_enabled_factor(
        &valence,
        &user,
        FIXTURE_SECRET_B32.into(),
        None,
        Some(5),
        Some(locked_until),
    )
    .await;

    let err = verify_code_against_factor(&valence, &factor, "000000", Utc::now())
        .await
        .expect_err("locked");
    assert!(matches!(err, StepUpError::StepUpRateLimited));
    assert_eq!(err.reason_class(), "step_up_rate_limited");
}

#[tokio::test]
async fn corrupt_sealed_secret_fails_closed_sad() {
    std::env::set_var("LEPTON_TOTP_ALLOW_TEST_SEAL_KEY", "1");
    let valence = system_valence("step_up_corrupt_seal").await;
    let user = seed_user(&valence).await;
    let (_id, factor) = seed_enabled_factor(
        &valence,
        &user,
        "v1:AAAACorruptSealedBlobNotDecryptable==".into(),
        None,
        None,
        None,
    )
    .await;

    let err = verify_code_against_factor(&valence, &factor, "123456", Utc::now())
        .await
        .expect_err("corrupt");
    assert!(matches!(err, StepUpError::TotpSecret));
    assert_eq!(err.reason_class(), "totp_secret");
    let msg = err.to_string();
    assert!(!msg.contains("AAAACorrupt"));
    assert!(!msg.contains(FIXTURE_SECRET_B32));
}

#[tokio::test]
async fn legacy_plaintext_verify_reseals_v1_happy() {
    std::env::set_var("LEPTON_TOTP_ALLOW_TEST_SEAL_KEY", "1");
    let valence = system_valence("step_up_legacy_migrate").await;
    let user = seed_user(&valence).await;
    let (factor_id, factor) =
        seed_enabled_factor(&valence, &user, FIXTURE_SECRET_B32.into(), None, None, None).await;
    assert!(
        !factor.secret_sealed().starts_with("v1:"),
        "fixture must start as legacy plaintext"
    );

    let totp = fixture_totp();
    let now = Utc::now();
    let code = totp.generate(now.timestamp().cast_unsigned());

    verify_code_against_factor(&valence, &factor, &code, now)
        .await
        .expect("legacy verify");

    let migrated = TotpFactor::get(&factor_id, &valence)
        .await
        .expect("get")
        .expect("present");
    assert!(
        migrated.secret_sealed().starts_with("v1:"),
        "successful verify must re-seal legacy plaintext to v1: envelope, got {}",
        migrated.secret_sealed()
    );
    assert!(!migrated.secret_sealed().contains(FIXTURE_SECRET_B32));
}
