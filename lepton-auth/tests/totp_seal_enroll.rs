//! TOTP enroll persists an AEAD-sealed secret (not raw base32) when seal key is on.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

use chrono::Utc;
use lepton_auth::totp::{
    begin_totp_enroll, confirm_totp_enroll, manual_secret_from_otpauth_uri,
    verify_totp_against_sealed,
};
use lepton_host_adapter::auth::hash_password;
use lepton_host_adapter::generated::{TotpFactor, User, UserStatus, UserUserType};
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
    let created = User::create_used(user, valence, valence::use_!(r#"**Test:** Fixture **User** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#)).await.expect("create user");
    created.id().cloned().expect("user id")
}

#[tokio::test]
async fn enroll_stores_aead_sealed_secret_happy() {
    std::env::set_var("LEPTON_TOTP_ALLOW_TEST_SEAL_KEY", "1");
    let valence = system_valence("totp_seal_enroll_happy").await;
    let user = seed_user(&valence).await;

    let pending = begin_totp_enroll(&valence, &user, "seal@example.com", "UF")
        .await
        .expect("begin enroll");

    let factor = TotpFactor::get_used(&pending.factor_id, &valence, valence::use_!(r#"**Test:** While you set up your **authenticator app**, we **save your not-yet-confirmed authenticator setup** for your account—including a **sealed copy of the authenticator secret**—so the next step can check the code from your app and finish turning **two-factor** on. After the QR or setup link at enroll time, the product does not show that secret again; it only keeps the sealed copy to complete **enrollment**."#))
        .await
        .expect("get")
        .expect("factor");
    let sealed = factor.secret_sealed();
    assert!(
        sealed.starts_with("v1:"),
        "row must store AEAD envelope, got {sealed}"
    );
    assert!(
        !sealed.chars().all(|c| c.is_ascii_alphanumeric()),
        "sealed blob must not look like bare base32"
    );
    // otpauth URI still carries plaintext base32 for the authenticator QR — not the envelope.
    assert!(
        !pending.otpauth_uri.contains("v1:"),
        "otpauth must not embed the sealed envelope"
    );
    let open = manual_secret_from_otpauth_uri(&pending.otpauth_uri).expect("secret from uri");
    assert!(!open.is_empty());
    assert!(!sealed.contains(&open), "row must not store raw base32");
}

#[tokio::test]
async fn enroll_confirm_roundtrip_with_sealed_row_happy() {
    std::env::set_var("LEPTON_TOTP_ALLOW_TEST_SEAL_KEY", "1");
    let valence = system_valence("totp_seal_confirm_happy").await;
    let user = seed_user(&valence).await;

    let pending = begin_totp_enroll(&valence, &user, "confirm@example.com", "UF")
        .await
        .expect("begin");
    let open = manual_secret_from_otpauth_uri(&pending.otpauth_uri).expect("open secret");
    let secret_bytes = Secret::Encoded(open.clone()).to_bytes().expect("bytes");
    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes).expect("totp");
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let code = totp.generate(t);

    confirm_totp_enroll(&valence, &user, &pending.factor_id, &code)
        .await
        .expect("confirm");

    let factor = TotpFactor::get_used(&pending.factor_id, &valence, valence::use_!(r#"**Test:** While you set up your **authenticator app**, we **save your not-yet-confirmed authenticator setup** for your account—including a **sealed copy of the authenticator secret**—so the next step can check the code from your app and finish turning **two-factor** on. After the QR or setup link at enroll time, the product does not show that secret again; it only keeps the sealed copy to complete **enrollment**."#))
        .await
        .expect("get")
        .expect("factor");
    assert!(factor.enabled_at().is_some());
    assert!(
        factor.secret_sealed().starts_with("v1:"),
        "confirmed row stays sealed"
    );
    verify_totp_against_sealed(factor.secret_sealed(), &code, Some(t)).expect("verify sealed");
}
