//! TOTP recovery consume + disable after enroll.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

use chrono::Utc;
use lepton_auth::security::random_token_part;
use lepton_auth::totp::{
    begin_totp_enroll, confirm_totp_enroll, consume_totp_recovery_code, disable_totp,
    manual_secret_from_otpauth_uri, regenerate_totp_recovery_codes, TotpEnrollError,
};
use lepton_host_adapter::auth::hash_password;
use lepton_host_adapter::generated::{
    TotpFactor, TotpRecoveryCode, User, UserStatus, UserUserType,
};
use lepton_identity::ownership::bare_id_from_record;
use support::system_valence;
use totp_rs::{Algorithm, Secret, TOTP};
use valence::{Model, RecordId};

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

#[tokio::test]
async fn consume_recovery_happy() {
    let valence = system_valence("totp_recovery_happy").await;
    let user = seed_user(&valence).await;

    let codes = regenerate_totp_recovery_codes(&valence, &user)
        .await
        .expect("regenerate");
    assert_eq!(codes.len(), 8);

    consume_totp_recovery_code(&valence, &user, &codes[0])
        .await
        .expect("consume");

    let uid = bare_id_from_record(&user);
    let rows = TotpRecoveryCode::get_from_user_id(&uid, &valence)
        .await
        .expect("list");
    let used_count = rows.iter().filter(|r| r.used_at().is_some()).count();
    assert_eq!(used_count, 1);
}

#[tokio::test]
async fn consume_recovery_reuse_sad() {
    let valence = system_valence("totp_recovery_reuse").await;
    let user = seed_user(&valence).await;
    let codes = regenerate_totp_recovery_codes(&valence, &user)
        .await
        .expect("regenerate");

    consume_totp_recovery_code(&valence, &user, &codes[0])
        .await
        .expect("first consume");
    let err = consume_totp_recovery_code(&valence, &user, &codes[0])
        .await
        .expect_err("reuse");
    assert!(matches!(err, TotpEnrollError::Mismatch));
    assert_eq!(err.reason_class(), "mismatch");
    assert!(!err.to_string().contains(&codes[0]));
}

#[tokio::test]
async fn consume_recovery_wrong_sad() {
    let valence = system_valence("totp_recovery_wrong").await;
    let user = seed_user(&valence).await;
    let _codes = regenerate_totp_recovery_codes(&valence, &user)
        .await
        .expect("regenerate");

    let bogus = random_token_part(8);
    let err = consume_totp_recovery_code(&valence, &user, &bogus)
        .await
        .expect_err("wrong");
    assert!(matches!(err, TotpEnrollError::Mismatch));
    assert!(!err.to_string().contains(&bogus));
}

#[tokio::test]
async fn disable_totp_after_enroll_happy() {
    std::env::set_var("LEPTON_TOTP_ALLOW_TEST_SEAL_KEY", "1");
    let valence = system_valence("totp_disable_after_enroll").await;
    let user = seed_user(&valence).await;

    let pending = begin_totp_enroll(&valence, &user, "a@example.com", "UF")
        .await
        .expect("begin");
    let secret = manual_secret_from_otpauth_uri(&pending.otpauth_uri).expect("otpauth secret");
    let secret_bytes = Secret::Encoded(secret).to_bytes().expect("bytes");
    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes).expect("totp");
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let code = totp.generate(t);
    confirm_totp_enroll(&valence, &user, &pending.factor_id, &code)
        .await
        .expect("confirm");
    let _codes = regenerate_totp_recovery_codes(&valence, &user)
        .await
        .expect("regen");

    disable_totp(&valence, &user).await.expect("disable");
    let uid = bare_id_from_record(&user);
    let left = TotpFactor::get_from_user_id(&uid, &valence)
        .await
        .expect("list");
    assert!(
        left.is_empty(),
        "factors should be gone, got {}",
        left.len()
    );
    let recovery = TotpRecoveryCode::get_from_user_id(&uid, &valence)
        .await
        .expect("recovery list");
    assert!(
        recovery.is_empty(),
        "recovery codes should be gone, got {}",
        recovery.len()
    );
}
