//! `AuthDevice` register / confirm / list / revoke under the session actor
//! (no System elevation), plus DTO checks that secret fields never serialize.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use crate::support;

use chrono::Utc;
use lepton_auth::devices::{
    confirm_auth_device, list_auth_devices, register_auth_device, revoke_auth_device,
    AuthDeviceKind, AuthDeviceView, DeviceError, PendingAuthDevice, PendingWebauthnAssertion,
    PendingWebauthnRegistration, RegisteredWebauthnDevice,
};
use lepton_host_adapter::auth::hash_password;
use lepton_host_adapter::generated::{AuthDevice, User, UserStatus, UserUserType};
use lepton_identity::ownership::bare_id_from_record;
use support::{system_valence, user_valence};
use valence::Model;

async fn seed_user(valence: &valence::Valence) -> valence::RecordId {
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
    let created = User::create(user, valence, valence::use_!(r"**Test:** Fixture **User** save for `tests` so the suite can seed device owners. CI and developers running the suite only."))
        .await
        .expect("create user");
    created.id().cloned().expect("id")
}

#[tokio::test]
async fn owner_session_registers_confirms_lists_and_revokes_device() {
    let sys = system_valence("device_owner_seed").await;
    let user = seed_user(&sys).await;
    let session = user_valence(&sys, bare_id_from_record(&user));

    let pending = register_auth_device(&session, &user, AuthDeviceKind::TrustedBrowser, "Laptop")
        .await
        .expect("register under session actor");
    confirm_auth_device(&session, &user, &pending.device_id, &pending.confirm_code)
        .await
        .expect("confirm under session actor");

    let listed = list_auth_devices(&session, &user).await.expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].label, "Laptop");
    assert!(listed[0].trusted_at.is_some());

    revoke_auth_device(&session, &user, &pending.device_id)
        .await
        .expect("revoke under session actor");
    let listed = list_auth_devices(&session, &user).await.expect("list");
    assert!(listed[0].revoked_at.is_some());
}

#[tokio::test]
async fn other_user_cannot_confirm_or_revoke_device() {
    let sys = system_valence("device_owner_seed").await;
    let owner = seed_user(&sys).await;
    let other = seed_user(&sys).await;
    let owner_session = user_valence(&sys, bare_id_from_record(&owner));
    let other_session = user_valence(&sys, bare_id_from_record(&other));

    let pending = register_auth_device(
        &owner_session,
        &owner,
        AuthDeviceKind::TrustedBrowser,
        "Laptop",
    )
    .await
    .expect("register");

    let confirm = confirm_auth_device(
        &other_session,
        &other,
        &pending.device_id,
        &pending.confirm_code,
    )
    .await;
    assert!(confirm.is_err(), "non-owner must not confirm: {confirm:?}");
    let revoke = revoke_auth_device(&other_session, &other, &pending.device_id).await;
    assert!(revoke.is_err(), "non-owner must not revoke: {revoke:?}");

    // The owner's device is untouched.
    let row = AuthDevice::get(&pending.device_id, &sys, valence::use_!(r"**Test:** Fixture **Auth Device** load for `tests` so the suite can assert a non-owner left the row unchanged. CI and developers running the suite only."))
        .await
        .expect("get")
        .expect("row");
    assert!(row.revoked_at().is_none());
    assert!(row.trusted_at().is_none());
}

#[tokio::test]
async fn other_user_lists_no_devices_of_owner() {
    let sys = system_valence("device_owner_seed").await;
    let owner = seed_user(&sys).await;
    let other = seed_user(&sys).await;
    let owner_session = user_valence(&sys, bare_id_from_record(&owner));
    let other_session = user_valence(&sys, bare_id_from_record(&other));
    register_auth_device(
        &owner_session,
        &owner,
        AuthDeviceKind::TrustedBrowser,
        "Laptop",
    )
    .await
    .expect("register");

    // Listing is keyed by the caller's own user; a foreign id yields no usable rows.
    let listed = list_auth_devices(&other_session, &owner).await;
    assert!(
        listed.map_or(true, |rows| rows.is_empty()),
        "foreign session must not see the owner's devices"
    );
}

#[tokio::test]
async fn anonymous_actor_cannot_register_device() {
    let sys = system_valence("device_owner_seed").await;
    let user = seed_user(&sys).await;
    let anon = sys.with_actor(valence::Actor::Anonymous);
    let result = register_auth_device(&anon, &user, AuthDeviceKind::TrustedBrowser, "Laptop").await;
    assert!(
        matches!(result, Err(DeviceError::Store | DeviceError::UserMissing)),
        "anonymous register must fail: {result:?}"
    );
}

#[test]
fn device_dtos_never_serialize_secret_fields() {
    let view = AuthDeviceView {
        id: "d1".into(),
        kind: AuthDeviceKind::WebAuthn,
        label: "Key".into(),
        credential_id: Some("cred".into()),
        sign_count: Some(1),
        trusted_at: None,
        last_seen_at: None,
        revoked_at: None,
    };
    let pending = PendingAuthDevice {
        device_id: "d1".into(),
        confirm_code: "ABCD1234".into(),
    };
    let jsons = [
        serde_json::to_string(&view).unwrap(),
        serde_json::to_string(&pending).unwrap(),
    ];
    for json in &jsons {
        for key in [
            "confirm_secret_hash",
            "binding_secret_hash",
            "passkey_json",
            "state_json",
            "$argon2",
        ] {
            assert!(!json.contains(key), "{json} leaks {key}");
        }
    }
    let webauthn = [
        serde_json::to_string(&PendingWebauthnRegistration {
            ceremony_id: "c1".into(),
            creation_options: serde_json::json!({"challenge": "x"}),
        })
        .unwrap(),
        serde_json::to_string(&PendingWebauthnAssertion {
            ceremony_id: "c1".into(),
            request_options: serde_json::json!({"challenge": "x"}),
        })
        .unwrap(),
        serde_json::to_string(&RegisteredWebauthnDevice {
            device_id: "d1".into(),
            credential_id: "cred".into(),
        })
        .unwrap(),
    ];
    for json in &webauthn {
        for key in ["passkey_json", "state_json", "secret_hash", "$argon2"] {
            assert!(!json.contains(key), "{json} leaks {key}");
        }
    }
}
