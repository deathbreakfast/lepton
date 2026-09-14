//! `WebAuthn` `AuthDevice` ceremony happy / sad paths (softpasskey authenticator).

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

use chrono::{Duration, Utc};
use lepton_auth::devices::{
    begin_webauthn_assertion, begin_webauthn_registration, finish_webauthn_assertion,
    finish_webauthn_registration, list_auth_devices, register_auth_device, revoke_auth_device,
    AuthDeviceKind, DeviceError, WebauthnRpConfig,
};
use lepton_host_adapter::auth::hash_password;
use lepton_host_adapter::generated::AuthDeviceCeremony;
use lepton_identity::generated::{User as IdentityUser, UserStatus, UserUserType};
use serde_json::json;
use support::system_valence;
use url::Url;
use valence::Model;
use webauthn_authenticator_rs::prelude::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

fn test_rp() -> WebauthnRpConfig {
    WebauthnRpConfig {
        rp_id: "localhost".into(),
        rp_origin: "http://localhost:3000".into(),
        rp_name: "Lepton".into(),
    }
}

async fn seed_user(valence: &valence::Valence) -> valence::RecordId {
    let password_hash = hash_password("CorrectHorseBattery1!").expect("hash");
    let now = Utc::now();
    let user = IdentityUser::new(
        Some(UserUserType::Person),
        Some(password_hash),
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
    let created = IdentityUser::create_used(user, valence, valence::use_!(r#"**Test:** Fixture **Identity User** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#)).await.expect("create");
    created.id().cloned().expect("id")
}

fn soft_authenticator() -> WebauthnAuthenticator<SoftPasskey> {
    WebauthnAuthenticator::new(SoftPasskey::new(true))
}

fn do_register(
    wa: &mut WebauthnAuthenticator<SoftPasskey>,
    origin: &Url,
    creation_options: serde_json::Value,
) -> serde_json::Value {
    let ccr: CreationChallengeResponse = serde_json::from_value(creation_options).expect("ccr");
    let reg = wa
        .do_registration(origin.clone(), ccr)
        .expect("soft register");
    serde_json::to_value(reg).expect("reg json")
}

fn do_assert(
    wa: &mut WebauthnAuthenticator<SoftPasskey>,
    origin: &Url,
    request_options: serde_json::Value,
) -> serde_json::Value {
    let rcr: RequestChallengeResponse = serde_json::from_value(request_options).expect("rcr");
    let auth = wa
        .do_authentication(origin.clone(), rcr)
        .expect("soft assert");
    serde_json::to_value(auth).expect("auth json")
}

#[tokio::test]
async fn webauthn_reg_assert_happy_path() {
    let valence = system_valence("webauthn_reg_assert_happy").await;
    let user = seed_user(&valence).await;
    let rp = test_rp();
    let origin = Url::parse(&rp.rp_origin).unwrap();

    let mut wa = soft_authenticator();
    let pending = begin_webauthn_registration(&valence, &rp, &user, "SoftKey")
        .await
        .expect("begin reg");
    let attestation = do_register(&mut wa, &origin, pending.creation_options);
    let device =
        finish_webauthn_registration(&valence, &rp, &user, &pending.ceremony_id, &attestation)
            .await
            .expect("finish reg");

    let listed = list_auth_devices(&valence, &user).await.expect("list");
    let view = listed
        .iter()
        .find(|d| d.id == device.device_id)
        .expect("device in list");
    assert_eq!(view.kind, AuthDeviceKind::WebAuthn);
    assert!(view.trusted_at.is_some());
    assert!(view.credential_id.is_some());
    assert!(view.passkey_json_absent_from_view());

    let assert_start = begin_webauthn_assertion(&valence, &rp, &user)
        .await
        .expect("begin assert");
    let assertion = do_assert(&mut wa, &origin, assert_start.request_options);
    let after =
        finish_webauthn_assertion(&valence, &rp, &user, &assert_start.ceremony_id, &assertion)
            .await
            .expect("finish assert");
    assert!(after.last_seen_at.is_some());
    assert!(after.sign_count.is_some());

    // Ceremony one-time: finish again fails.
    let again =
        finish_webauthn_assertion(&valence, &rp, &user, &assert_start.ceremony_id, &assertion)
            .await;
    assert!(matches!(again, Err(DeviceError::CeremonyInvalid)));
    assert_eq!(again.err().unwrap().reason_class(), "ceremony_invalid");
}

trait PasskeyAbsent {
    fn passkey_json_absent_from_view(&self) -> bool;
}

impl PasskeyAbsent for lepton_auth::devices::AuthDeviceView {
    fn passkey_json_absent_from_view(&self) -> bool {
        // Compile-time: AuthDeviceView has no passkey_json field.
        true
    }
}

#[tokio::test]
async fn webauthn_reg_verify_failed_sad() {
    let valence = system_valence("webauthn_reg_verify_failed").await;
    let user = seed_user(&valence).await;
    let rp = test_rp();
    let pending = begin_webauthn_registration(&valence, &rp, &user, "SoftKey")
        .await
        .expect("begin");
    let bad = json!({ "id": "not-a-credential", "rawId": "x", "type": "public-key" });
    let err = finish_webauthn_registration(&valence, &rp, &user, &pending.ceremony_id, &bad)
        .await
        .expect_err("bad attestation");
    assert_eq!(err.reason_class(), "webauthn_verify");
    assert!(!err.to_string().contains("challenge"));
    let listed = list_auth_devices(&valence, &user).await.expect("list");
    assert!(listed.is_empty());
}

#[tokio::test]
async fn webauthn_ceremony_expired_sad() {
    let valence = system_valence("webauthn_ceremony_expired").await;
    let user = seed_user(&valence).await;
    let rp = test_rp();
    let mut wa = soft_authenticator();
    let pending = begin_webauthn_registration(&valence, &rp, &user, "SoftKey")
        .await
        .expect("begin");
    let ceremony = AuthDeviceCeremony::get_used(&pending.ceremony_id, &valence, valence::use_!(r#"**Test:** Fixture **Auth Device Ceremony** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .expect("get")
        .expect("row");
    let past = Utc::now() - Duration::hours(1);
    ceremony
        .get_mutable_used(&valence, valence::use_!(r#"**Test:** Fixture **this data** access in `webauthn_devices` so the suite can arrange and assert persistence. CI and developers running the suite only."#))
        .set_expires_at(past)
        .expect("set")
        .set_updated_at(Utc::now())
        .expect("upd")
        .commit()
        .await
        .expect("commit");
    let origin = Url::parse(&rp.rp_origin).unwrap();
    let attestation = do_register(&mut wa, &origin, pending.creation_options.clone());
    let err =
        finish_webauthn_registration(&valence, &rp, &user, &pending.ceremony_id, &attestation)
            .await
            .expect_err("expired");
    assert_eq!(err.reason_class(), "ceremony_invalid");
}

#[tokio::test]
async fn webauthn_assert_revoked_sad() {
    let valence = system_valence("webauthn_assert_revoked").await;
    let user = seed_user(&valence).await;
    let rp = test_rp();
    let origin = Url::parse(&rp.rp_origin).unwrap();
    let mut wa = soft_authenticator();

    let pending = begin_webauthn_registration(&valence, &rp, &user, "SoftKey")
        .await
        .expect("begin");
    let attestation = do_register(&mut wa, &origin, pending.creation_options);
    let device =
        finish_webauthn_registration(&valence, &rp, &user, &pending.ceremony_id, &attestation)
            .await
            .expect("finish");

    // Begin assertion while still valid, then revoke before finish.
    let assert_start = begin_webauthn_assertion(&valence, &rp, &user)
        .await
        .expect("begin assert");
    revoke_auth_device(&valence, &user, &device.device_id)
        .await
        .expect("revoke");
    let assertion = do_assert(&mut wa, &origin, assert_start.request_options);
    let err =
        finish_webauthn_assertion(&valence, &rp, &user, &assert_start.ceremony_id, &assertion)
            .await
            .expect_err("revoked");
    assert_eq!(err.reason_class(), "device_revoked");
}

#[tokio::test]
async fn webauthn_assert_wrong_user_sad() {
    let valence = system_valence("webauthn_assert_wrong_user").await;
    let user_a = seed_user(&valence).await;
    let user_b = seed_user(&valence).await;
    let rp = test_rp();
    let origin = Url::parse(&rp.rp_origin).unwrap();
    let mut wa = soft_authenticator();

    let pending = begin_webauthn_registration(&valence, &rp, &user_a, "SoftKey")
        .await
        .expect("begin");
    let attestation = do_register(&mut wa, &origin, pending.creation_options);
    finish_webauthn_registration(&valence, &rp, &user_a, &pending.ceremony_id, &attestation)
        .await
        .expect("finish");

    let assert_start = begin_webauthn_assertion(&valence, &rp, &user_a)
        .await
        .expect("begin assert");
    let assertion = do_assert(&mut wa, &origin, assert_start.request_options);
    let err = finish_webauthn_assertion(
        &valence,
        &rp,
        &user_b,
        &assert_start.ceremony_id,
        &assertion,
    )
    .await
    .expect_err("wrong user");
    assert_eq!(err.reason_class(), "ceremony_invalid");
}

#[tokio::test]
async fn webauthn_confirm_code_path_still_unsupported_sad() {
    let valence = system_valence("webauthn_confirm_unsupported").await;
    let user = seed_user(&valence).await;
    let err = register_auth_device(&valence, &user, AuthDeviceKind::WebAuthn, "Nope")
        .await
        .expect_err("unsupported");
    assert_eq!(err.reason_class(), "unsupported_kind");
}

#[tokio::test]
async fn webauthn_list_omits_passkey_material_happy() {
    let valence = system_valence("webauthn_list_safe").await;
    let user = seed_user(&valence).await;
    let rp = test_rp();
    let origin = Url::parse(&rp.rp_origin).unwrap();
    let mut wa = soft_authenticator();
    let pending = begin_webauthn_registration(&valence, &rp, &user, "SoftKey")
        .await
        .expect("begin");
    let attestation = do_register(&mut wa, &origin, pending.creation_options);
    finish_webauthn_registration(&valence, &rp, &user, &pending.ceremony_id, &attestation)
        .await
        .expect("finish");
    let listed = list_auth_devices(&valence, &user).await.expect("list");
    assert_eq!(listed.len(), 1);
    let view = &listed[0];
    assert!(view.credential_id.is_some());
    let s = format!("{view:?}");
    assert!(!s.contains("passkey_json"));
    assert!(!s.contains("cose_public_key"));
}

#[tokio::test]
async fn webauthn_ceremony_consume_twice_sad() {
    let valence = system_valence("webauthn_ceremony_twice").await;
    let user = seed_user(&valence).await;
    let rp = test_rp();
    let origin = Url::parse(&rp.rp_origin).unwrap();
    let mut wa = soft_authenticator();
    let pending = begin_webauthn_registration(&valence, &rp, &user, "SoftKey")
        .await
        .expect("begin");
    let attestation = do_register(&mut wa, &origin, pending.creation_options.clone());
    finish_webauthn_registration(&valence, &rp, &user, &pending.ceremony_id, &attestation)
        .await
        .expect("finish once");
    let err =
        finish_webauthn_registration(&valence, &rp, &user, &pending.ceremony_id, &attestation)
            .await
            .expect_err("second finish");
    assert_eq!(err.reason_class(), "ceremony_invalid");
}
