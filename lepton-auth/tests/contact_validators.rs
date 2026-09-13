//! Contact format validators: E.164 phone + email at the schema layer.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

use chrono::Utc;
use lepton_auth::contacts::{add_account_email, add_account_phone, ContactError};
use lepton_host_adapter::auth::hash_password;
use lepton_host_adapter::generated::{
    Account, AccountMembership, AccountMembershipRole, AccountPhone, AccountPlan, AccountStatus,
    User, UserStatus, UserUserType,
};
use support::system_valence;
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

async fn seed_account_with_membership(valence: &valence::Valence, user: &RecordId) -> RecordId {
    let now = Utc::now();
    let account = Account::new(
        "validators@example.test".to_string(),
        user.clone(),
        Some(AccountPlan::Free),
        Some(AccountStatus::Active),
        None,
        None,
        now,
        now,
    )
    .expect("account");
    let account = Account::create_used(account, valence, valence::use_!(r#"**Test:** Fixture **Account** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .expect("create account");
    let account_id = account.id().cloned().expect("account id");
    let membership = AccountMembership::new(
        account_id.clone(),
        user.clone(),
        AccountMembershipRole::Owner,
        now,
        now,
    )
    .expect("membership");
    AccountMembership::create_used(membership, valence, valence::use_!(r#"**Test:** Fixture **Account Membership** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .expect("create membership");
    account_id
}

#[test]
fn account_phone_new_accepts_valid_e164() {
    let now = Utc::now();
    let account = RecordId::new("account", "a1");
    let phone = AccountPhone::new(account, "+15555550100".into(), None, now, now);
    assert!(phone.is_ok());
}

#[test]
fn account_phone_new_rejects_non_e164() {
    let now = Utc::now();
    let account = RecordId::new("account", "a1");
    for bad in ["", "555", "+", "+0123", "15555550100"] {
        let err = AccountPhone::new(account.clone(), bad.into(), None, now, now);
        assert!(err.is_err(), "expected reject for {bad:?}");
    }
}

#[tokio::test]
async fn add_account_phone_valid_e164_happy_path() {
    let valence = system_valence("contact_phone_valid").await;
    let user = seed_user(&valence).await;
    let account = seed_account_with_membership(&valence, &user).await;
    let phone = add_account_phone(&valence, &account, "+15555550100")
        .await
        .expect("add phone");
    assert_eq!(phone.e164(), "+15555550100");
}

#[tokio::test]
async fn add_account_phone_invalid_e164_maps_to_store() {
    let valence = system_valence("contact_phone_invalid").await;
    let user = seed_user(&valence).await;
    let account = seed_account_with_membership(&valence, &user).await;
    let err = add_account_phone(&valence, &account, "555-0100")
        .await
        .expect_err("non-E.164");
    assert_eq!(err.reason_class(), "store");
    assert!(!err.to_string().contains("555"));
    assert!(matches!(err, ContactError::Store));
}

#[tokio::test]
async fn add_account_email_invalid_maps_to_store() {
    let valence = system_valence("contact_email_invalid").await;
    let user = seed_user(&valence).await;
    let account = seed_account_with_membership(&valence, &user).await;
    let err = add_account_email(&valence, &account, "not-an-email")
        .await
        .expect_err("bad email");
    assert_eq!(err.reason_class(), "store");
    assert!(!err.to_string().contains('@'));
    assert!(!err.to_string().contains("not-an-email"));
    assert!(matches!(err, ContactError::Store));
}

#[tokio::test]
async fn add_account_email_valid_happy_path() {
    let valence = system_valence("contact_email_valid").await;
    let user = seed_user(&valence).await;
    let account = seed_account_with_membership(&valence, &user).await;
    let email = add_account_email(&valence, &account, "ok@example.test")
        .await
        .expect("add email");
    assert_eq!(email.address(), "ok@example.test");
}
