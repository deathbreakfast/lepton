//! `execute_change_password` under session User valence (owner PHC read).

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

use chrono::Utc;
use lepton_auth::account_api::ssr::{execute_change_password, ChangePasswordRequest};
use lepton_host_adapter::auth::{hash_password, User as AuthUser};
use lepton_host_adapter::generated::{User, UserStatus, UserUserType};
use lepton_identity::ownership::bare_id_from_record;
use leptos::prelude::ServerFnError;
use support::{system_valence, user_valence};
use valence::Model;

use argon2::{password_hash::PasswordHash, PasswordVerifier};

const CURRENT_PASSWORD: &str = "CorrectHorseBattery1!";
const NEW_PASSWORD: &str = "CorrectHorseBattery2!";

async fn seed_person(valence: &valence::Valence, password: &str) -> (AuthUser, String) {
    let phc = hash_password(password).expect("hash");
    let now = Utc::now();
    let user = User::new(
        Some(UserUserType::Person),
        Some(phc),
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
    let created = User::create_used(user, valence, valence::use_!("create User in lepton-auth/tests/change_password.rs; Valence persistence for this feature path; typed store; visible to test harness.")).await.expect("create user");
    let bare = bare_id_from_record(created.id().expect("id"));
    let auth_user = AuthUser::from_generated(
        &created,
        "alice@example.test".into(),
        true,
        None,
        None,
        vec!["owner".into()],
    );
    (auth_user, bare)
}

#[tokio::test]
async fn change_password_owner_valence_happy_path() {
    let sys = system_valence("change_password_owner").await;
    let (auth_user, bare) = seed_person(&sys, CURRENT_PASSWORD).await;
    let owner_v = user_valence(&sys, &bare);

    execute_change_password(
        &owner_v,
        &auth_user,
        ChangePasswordRequest {
            current_password: CURRENT_PASSWORD.into(),
            new_password: NEW_PASSWORD.into(),
            confirm_password: NEW_PASSWORD.into(),
        },
    )
    .await
    .expect("change password");

    let reloaded = User::get_used(&bare, &sys, valence::use_!("get User in lepton-auth/tests/change_password.rs; Valence persistence for this feature path; typed store; visible to test harness.")).await.expect("get").expect("user");
    let new_phc = reloaded.password_hash().expect("new hash");

    let parsed = PasswordHash::new(new_phc).expect("parse");
    argon2::Argon2::default()
        .verify_password(NEW_PASSWORD.as_bytes(), &parsed)
        .expect("new password verifies");
    assert!(argon2::Argon2::default()
        .verify_password(CURRENT_PASSWORD.as_bytes(), &parsed)
        .is_err());
}

#[tokio::test]
async fn change_password_wrong_current_sad() {
    let sys = system_valence("change_password_wrong_current").await;
    let (auth_user, bare) = seed_person(&sys, CURRENT_PASSWORD).await;
    let owner_v = user_valence(&sys, &bare);

    let before = User::get_used(&bare, &sys, valence::use_!("get User in lepton-auth/tests/change_password.rs; Valence persistence for this feature path; typed store; visible to test harness."))
        .await
        .expect("get")
        .expect("user")
        .password_hash()
        .expect("phc")
        .clone();

    let err = execute_change_password(
        &owner_v,
        &auth_user,
        ChangePasswordRequest {
            current_password: "WrongPassword!!!!1".into(),
            new_password: NEW_PASSWORD.into(),
            confirm_password: NEW_PASSWORD.into(),
        },
    )
    .await
    .expect_err("wrong current must fail");

    match err {
        ServerFnError::Args(msg) => {
            assert!(
                msg.contains("Current password is incorrect"),
                "unexpected args: {msg}"
            );
        }
        other => panic!("expected Args, got {other:?}"),
    }

    let after = User::get_used(&bare, &sys, valence::use_!("get User in lepton-auth/tests/change_password.rs; Valence persistence for this feature path; typed store; visible to test harness."))
        .await
        .expect("get")
        .expect("user")
        .password_hash()
        .expect("phc")
        .clone();
    assert_eq!(before, after, "hash must be unchanged on failure");
}
