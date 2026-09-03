//! `execute_wipe_account`: Owner gates, password, confirm phrase, TOTP step-up.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

use chrono::Utc;
use lepton_auth::account_api::ssr::{execute_wipe_account, WipeAccountRequest};
use lepton_auth::account_api::WIPE_CONFIRM_PHRASE;
use lepton_auth::security::random_token_part;
use lepton_host_adapter::auth::{hash_password, User as AuthUser};
use lepton_host_adapter::generated::{
    Account, AccountEmail, AccountMembership, AccountMembershipRole, AccountPlan, AccountStatus,
    TotpFactor, User, UserStatus, UserUserType,
};
use lepton_identity::ownership::bare_id_from_record;
use leptos::prelude::ServerFnError;
use support::system_valence;
use totp_rs::{Algorithm, Secret, TOTP};
use valence::{Model, RecordId};

const PASSWORD: &str = "CorrectHorseBattery1!";
const FIXTURE_SECRET_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

async fn seed_owner_account(
    valence: &valence::Valence,
    email: &str,
    role: AccountMembershipRole,
    roles: Vec<String>,
) -> (AuthUser, RecordId, RecordId) {
    let now = Utc::now();
    let user = User::new(
        Some(UserUserType::Person),
        Some(hash_password(PASSWORD).expect("hash")),
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
    let user_id = created.id().cloned().expect("user id");

    let account = Account::new(
        email.to_string(),
        user_id.clone(),
        Some(AccountPlan::Free),
        Some(AccountStatus::Active),
        None,
        None,
        now,
        now,
    )
    .expect("account");
    let account = Account::create(account, valence)
        .await
        .expect("create account");
    let account_id = account.id().cloned().expect("account id");

    let membership = AccountMembership::new(account_id.clone(), user_id.clone(), role, now, now)
        .expect("membership");
    AccountMembership::create(membership, valence)
        .await
        .expect("create membership");

    let email_row =
        AccountEmail::new(account_id.clone(), email.into(), Some(now), now, now).expect("email");
    let email_row = AccountEmail::create(email_row, valence)
        .await
        .expect("create email");
    let email_id = email_row.id().cloned().expect("email id");

    User::get(&bare_id_from_record(&user_id), valence)
        .await
        .expect("get")
        .expect("user")
        .get_mutable(valence)
        .set_primary_email(email_id.clone())
        .expect("login")
        .set_updated_at(now)
        .expect("ts")
        .commit()
        .await
        .expect("commit");

    Account::get(&bare_id_from_record(&account_id), valence)
        .await
        .expect("get")
        .expect("account")
        .get_mutable(valence)
        .set_primary_email(email_id)
        .expect("primary")
        .set_updated_at(now)
        .expect("ts")
        .commit()
        .await
        .expect("commit");

    let auth_user = AuthUser::from_generated(
        &created,
        email.into(),
        true,
        None,
        Some(bare_id_from_record(&account_id)),
        roles,
    );
    (auth_user, user_id, account_id)
}

async fn seed_enabled_totp(valence: &valence::Valence, user: &RecordId) {
    let now = Utc::now();
    let factor_id = random_token_part(12);
    let factor = TotpFactor::new(
        user.clone(),
        FIXTURE_SECRET_B32.into(),
        None,
        None,
        None,
        Some(now),
        Some(now),
        now,
        now,
    )
    .expect("totp");
    TotpFactor::upsert(&factor_id, factor, valence)
        .await
        .expect("upsert");
}

fn current_totp_code() -> String {
    let secret = Secret::Encoded(FIXTURE_SECRET_B32.to_string())
        .to_bytes()
        .expect("secret");
    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret).expect("totp");
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    totp.generate(t)
}

fn assert_args_contains(err: ServerFnError, needle: &str) {
    match err {
        ServerFnError::Args(msg) => {
            assert!(msg.contains(needle), "unexpected args: {msg}");
        }
        other => panic!("expected Args, got {other:?}"),
    }
}

#[tokio::test]
async fn execute_wipe_account_happy() {
    let valence = system_valence("wipe_happy").await;
    let (auth_user, user_id, account_id) = seed_owner_account(
        &valence,
        "wipe-happy@example.test",
        AccountMembershipRole::Owner,
        vec!["owner".into()],
    )
    .await;

    execute_wipe_account(
        &valence,
        &auth_user,
        WipeAccountRequest {
            current_password: PASSWORD.into(),
            confirm_phrase: WIPE_CONFIRM_PHRASE.into(),
            totp_code: None,
        },
    )
    .await
    .expect("wipe");

    assert!(Account::get(&bare_id_from_record(&account_id), &valence)
        .await
        .expect("get")
        .is_none());
    assert!(User::get(&bare_id_from_record(&user_id), &valence)
        .await
        .expect("get")
        .is_none());
}

#[tokio::test]
async fn execute_wipe_account_bad_password() {
    let valence = system_valence("wipe_bad_password").await;
    let (auth_user, user_id, account_id) = seed_owner_account(
        &valence,
        "wipe-bad-pw@example.test",
        AccountMembershipRole::Owner,
        vec!["owner".into()],
    )
    .await;

    let err = execute_wipe_account(
        &valence,
        &auth_user,
        WipeAccountRequest {
            current_password: "WrongPassword!!!!1".into(),
            confirm_phrase: WIPE_CONFIRM_PHRASE.into(),
            totp_code: None,
        },
    )
    .await
    .expect_err("bad password");
    assert_args_contains(err, "Current password is incorrect");

    assert!(Account::get(&bare_id_from_record(&account_id), &valence)
        .await
        .expect("get")
        .is_some());
    assert!(User::get(&bare_id_from_record(&user_id), &valence)
        .await
        .expect("get")
        .is_some());
}

#[tokio::test]
async fn execute_wipe_account_bad_phrase_sad() {
    let valence = system_valence("wipe_bad_phrase").await;
    let (auth_user, user_id, account_id) = seed_owner_account(
        &valence,
        "wipe-bad-phrase@example.test",
        AccountMembershipRole::Owner,
        vec!["owner".into()],
    )
    .await;

    let err = execute_wipe_account(
        &valence,
        &auth_user,
        WipeAccountRequest {
            current_password: PASSWORD.into(),
            confirm_phrase: "delete".into(),
            totp_code: None,
        },
    )
    .await
    .expect_err("bad confirm phrase");
    assert_args_contains(err, "Type DELETE to confirm account wipe");

    assert!(Account::get(&bare_id_from_record(&account_id), &valence)
        .await
        .expect("get")
        .is_some());
    assert!(User::get(&bare_id_from_record(&user_id), &valence)
        .await
        .expect("get")
        .is_some());
}

#[tokio::test]
async fn execute_wipe_account_not_owner() {
    let valence = system_valence("wipe_not_owner").await;
    let (auth_user, user_id, account_id) = seed_owner_account(
        &valence,
        "wipe-admin@example.test",
        AccountMembershipRole::Admin,
        vec!["admin".into()],
    )
    .await;

    let err = execute_wipe_account(
        &valence,
        &auth_user,
        WipeAccountRequest {
            current_password: PASSWORD.into(),
            confirm_phrase: WIPE_CONFIRM_PHRASE.into(),
            totp_code: None,
        },
    )
    .await
    .expect_err("not owner");
    assert_args_contains(err, "Only the account owner");

    assert!(Account::get(&bare_id_from_record(&account_id), &valence)
        .await
        .expect("get")
        .is_some());
    assert!(User::get(&bare_id_from_record(&user_id), &valence)
        .await
        .expect("get")
        .is_some());
}

#[tokio::test]
async fn execute_wipe_account_totp_required() {
    let valence = system_valence("wipe_totp_required").await;
    let (auth_user, user_id, account_id) = seed_owner_account(
        &valence,
        "wipe-totp@example.test",
        AccountMembershipRole::Owner,
        vec!["owner".into()],
    )
    .await;
    seed_enabled_totp(&valence, &user_id).await;

    let err = execute_wipe_account(
        &valence,
        &auth_user,
        WipeAccountRequest {
            current_password: PASSWORD.into(),
            confirm_phrase: WIPE_CONFIRM_PHRASE.into(),
            totp_code: None,
        },
    )
    .await
    .expect_err("totp required");
    assert_args_contains(err, "Authenticator code is required");

    let err = execute_wipe_account(
        &valence,
        &auth_user,
        WipeAccountRequest {
            current_password: PASSWORD.into(),
            confirm_phrase: WIPE_CONFIRM_PHRASE.into(),
            totp_code: Some("000000".into()),
        },
    )
    .await
    .expect_err("bad totp");
    assert_args_contains(err, "Authenticator code is incorrect");

    assert!(Account::get(&bare_id_from_record(&account_id), &valence)
        .await
        .expect("get")
        .is_some());

    execute_wipe_account(
        &valence,
        &auth_user,
        WipeAccountRequest {
            current_password: PASSWORD.into(),
            confirm_phrase: WIPE_CONFIRM_PHRASE.into(),
            totp_code: Some(current_totp_code()),
        },
    )
    .await
    .expect("wipe with totp");

    assert!(Account::get(&bare_id_from_record(&account_id), &valence)
        .await
        .expect("get")
        .is_none());
}
