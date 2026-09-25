//! `AccountPhone` ownership, primaries, contacts APIs (TM-S2–S3, TM-C3–C6).

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

use chrono::Utc;
use lepton_auth::contacts::{
    add_account_phone, mark_account_phone_verified, set_account_primary_phone, set_primary_phone,
    ContactError,
};
use lepton_auth::identity_delete::{delete_account_phone, erase_account, IdentityDeleteError};
use lepton_host_adapter::auth::hash_password;
use lepton_host_adapter::generated::{
    Account, AccountMembership, AccountMembershipRole, AccountPhone, AccountPlan, AccountStatus,
    User, UserStatus, UserUserType,
};
use lepton_identity::ownership::bare_id_from_record;
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
    let created = User::create(user, valence, valence::use_!(r"**Test:** Fixture **User** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only.")).await.expect("create user");
    created.id().cloned().expect("user id")
}

async fn seed_account(valence: &valence::Valence, name: &str, user: &RecordId) -> RecordId {
    let now = Utc::now();
    let account = Account::new(
        name.to_string(),
        user.clone(),
        Some(AccountPlan::Free),
        Some(AccountStatus::Active),
        None,
        None,
        now,
        now,
    )
    .expect("account");
    let created = Account::create(account, valence, valence::use_!(r"**Test:** Fixture **Account** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("create account");
    created.id().cloned().expect("account id")
}

async fn seed_membership(
    valence: &valence::Valence,
    account: &RecordId,
    user: &RecordId,
) -> RecordId {
    let now = Utc::now();
    let membership = AccountMembership::new(
        account.clone(),
        user.clone(),
        AccountMembershipRole::Owner,
        now,
        now,
    )
    .expect("membership");
    let created = AccountMembership::create(membership, valence, valence::use_!(r"**Test:** Fixture **Account Membership** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("create membership");
    created.id().cloned().expect("membership id")
}

#[tokio::test]
async fn account_phone_erase_cascades_happy() {
    let valence = system_valence("phone_erase").await;
    let user = seed_user(&valence).await;
    let account = seed_account(&valence, "phone-erase", &user).await;
    seed_membership(&valence, &account, &user).await;

    let phone = add_account_phone(&valence, &account, "+15555550101")
        .await
        .expect("add");
    let phone_id = phone.id().cloned().expect("id");

    erase_account(&valence, &account).await.expect("erase");
    assert!(AccountPhone::get(&bare_id_from_record(&phone_id), &valence, valence::use_!(r"**Test:** Fixture **Account Phone** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("get")
        .is_none());
}

#[tokio::test]
async fn account_primary_phone_restrict_happy() {
    let valence = system_valence("phone_restrict_backup").await;
    let user = seed_user(&valence).await;
    let account = seed_account(&valence, "phone-restrict", &user).await;
    seed_membership(&valence, &account, &user).await;

    let primary = add_account_phone(&valence, &account, "+15555550102")
        .await
        .expect("add primary");
    mark_account_phone_verified(&valence, &primary)
        .await
        .expect("verify");
    let primary_id = primary.id().cloned().expect("id");
    set_account_primary_phone(&valence, &account, &primary_id)
        .await
        .expect("set primary");

    let backup = add_account_phone(&valence, &account, "+15555550103")
        .await
        .expect("add backup");
    let backup_id = backup.id().cloned().expect("id");

    delete_account_phone(&valence, &backup_id)
        .await
        .expect("delete backup");
    assert!(
        AccountPhone::get(&bare_id_from_record(&backup_id), &valence, valence::use_!(r"**Test:** Fixture **Account Phone** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
            .await
            .expect("get")
            .is_none()
    );
}

#[tokio::test]
async fn account_primary_phone_delete_primary_sad() {
    let valence = system_valence("phone_restrict_primary").await;
    let user = seed_user(&valence).await;
    let account = seed_account(&valence, "phone-primary-del", &user).await;
    seed_membership(&valence, &account, &user).await;

    let phone = add_account_phone(&valence, &account, "+15555550104")
        .await
        .expect("add");
    mark_account_phone_verified(&valence, &phone)
        .await
        .expect("verify");
    let phone_id = phone.id().cloned().expect("id");
    set_account_primary_phone(&valence, &account, &phone_id)
        .await
        .expect("set primary");

    let err = delete_account_phone(&valence, &phone_id)
        .await
        .expect_err("primary blocked");
    assert!(matches!(err, IdentityDeleteError::RestrictPrimary));
    assert_eq!(err.reason_class(), "restrict_primary");
}

#[tokio::test]
async fn add_account_phone_happy() {
    let valence = system_valence("add_phone").await;
    let user = seed_user(&valence).await;
    let account = seed_account(&valence, "add-phone", &user).await;
    seed_membership(&valence, &account, &user).await;

    let phone = add_account_phone(&valence, &account, "+15555550105")
        .await
        .expect("add");
    assert_eq!(
        bare_id_from_record(phone.account()),
        bare_id_from_record(&account)
    );
}

#[tokio::test]
async fn add_account_phone_invalid_sad() {
    let valence = system_valence("add_phone_bad").await;
    let user = seed_user(&valence).await;
    let account = seed_account(&valence, "add-phone-bad", &user).await;
    seed_membership(&valence, &account, &user).await;

    let err = add_account_phone(&valence, &account, "not-e164")
        .await
        .expect_err("invalid");
    assert!(matches!(err, ContactError::Store));
}

#[tokio::test]
async fn set_account_primary_phone_happy() {
    let valence = system_valence("set_acct_phone").await;
    let user = seed_user(&valence).await;
    let account = seed_account(&valence, "set-acct-phone", &user).await;
    seed_membership(&valence, &account, &user).await;

    let phone = add_account_phone(&valence, &account, "+15555550106")
        .await
        .expect("add");
    mark_account_phone_verified(&valence, &phone)
        .await
        .expect("verify");
    let phone_id = phone.id().cloned().expect("id");
    set_account_primary_phone(&valence, &account, &phone_id)
        .await
        .expect("set");

    let acct = Account::get(&bare_id_from_record(&account), &valence, valence::use_!(r"**Test:** Fixture **Account** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("get")
        .expect("account");
    assert_eq!(
        bare_id_from_record(acct.primary_phone().expect("primary")),
        bare_id_from_record(&phone_id)
    );
}

#[tokio::test]
async fn set_account_primary_phone_unverified_sad() {
    let valence = system_valence("set_acct_phone_unverified").await;
    let user = seed_user(&valence).await;
    let account = seed_account(&valence, "set-phone-uv", &user).await;
    seed_membership(&valence, &account, &user).await;

    let phone = add_account_phone(&valence, &account, "+15555550107")
        .await
        .expect("add");
    let phone_id = phone.id().cloned().expect("id");
    let err = set_account_primary_phone(&valence, &account, &phone_id)
        .await
        .expect_err("unverified");
    assert!(matches!(err, ContactError::Unverified));
    assert_eq!(err.reason_class(), "unverified_contact");
}

#[tokio::test]
async fn set_account_primary_phone_wrong_account_sad() {
    let valence = system_valence("set_acct_phone_wrong").await;
    let user_a = seed_user(&valence).await;
    let user_b = seed_user(&valence).await;
    let account_a = seed_account(&valence, "phone-a", &user_a).await;
    let account_b = seed_account(&valence, "phone-b", &user_b).await;
    seed_membership(&valence, &account_a, &user_a).await;
    seed_membership(&valence, &account_b, &user_b).await;

    let phone = add_account_phone(&valence, &account_a, "+15555550108")
        .await
        .expect("add");
    mark_account_phone_verified(&valence, &phone)
        .await
        .expect("verify");
    let phone_id = phone.id().cloned().expect("id");

    let err = set_account_primary_phone(&valence, &account_b, &phone_id)
        .await
        .expect_err("wrong account");
    assert!(matches!(
        err,
        ContactError::NotMember | ContactError::ContactMissing
    ));
}

#[tokio::test]
async fn set_primary_phone_happy() {
    let valence = system_valence("set_login_phone").await;
    let user = seed_user(&valence).await;
    let account = seed_account(&valence, "login-phone", &user).await;
    seed_membership(&valence, &account, &user).await;

    let phone = add_account_phone(&valence, &account, "+15555550109")
        .await
        .expect("add");
    mark_account_phone_verified(&valence, &phone)
        .await
        .expect("verify");
    let phone_id = phone.id().cloned().expect("id");
    set_primary_phone(&valence, &user, &phone_id)
        .await
        .expect("set login");

    let row = User::get(&bare_id_from_record(&user), &valence, valence::use_!(r"**Test:** Fixture **User** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("get")
        .expect("user");
    assert_eq!(
        bare_id_from_record(row.primary_phone().expect("login")),
        bare_id_from_record(&phone_id)
    );
}

#[tokio::test]
async fn set_primary_phone_non_member_sad() {
    let valence = system_valence("set_login_phone_nm").await;
    let owner = seed_user(&valence).await;
    let stranger = seed_user(&valence).await;
    let account = seed_account(&valence, "login-phone-nm", &owner).await;
    seed_membership(&valence, &account, &owner).await;

    let phone = add_account_phone(&valence, &account, "+15555550110")
        .await
        .expect("add");
    mark_account_phone_verified(&valence, &phone)
        .await
        .expect("verify");
    let phone_id = phone.id().cloned().expect("id");

    let err = set_primary_phone(&valence, &stranger, &phone_id)
        .await
        .expect_err("non-member");
    assert!(matches!(err, ContactError::ContactMissing));
}
