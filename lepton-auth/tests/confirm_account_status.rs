//! Confirm-account status flags (library path used by product status server fn).

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

use chrono::Utc;
use lepton_auth::account_api::{
    mask_email_for_display, mask_phone_for_display, ConfirmAccountStatus,
};
use lepton_auth::contacts::{
    add_account_phone, mark_account_phone_verified, set_account_primary_phone, set_primary_phone,
};
use lepton_auth::trust::{
    confirm_user, is_confirmed, primary_email_verified, primary_phone_verified,
};
use lepton_host_adapter::auth::hash_password;
use lepton_host_adapter::generated::{
    Account, AccountEmail, AccountMembership, AccountMembershipRole, AccountPlan, AccountStatus,
    User, UserStatus, UserUserType,
};
use support::system_valence;
use valence::{Model, RecordId};

async fn seed_user_with_email(
    valence: &valence::Valence,
    email: &str,
    verified: bool,
) -> (RecordId, RecordId) {
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
    let account_created = Account::create_used(account, valence, valence::use_!(r#"**Test:** Fixture **Account** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .expect("create account");
    let account_id = account_created.id().cloned().expect("account id");

    AccountMembership::create_used(
        AccountMembership::new(
            account_id.clone(),
            user_id.clone(),
            AccountMembershipRole::Owner,
            now,
            now,
        )
        .expect("membership"),
        valence,
        valence::use_!(r#"**Test:** Fixture **Account Membership** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#),
    )
    .await
    .expect("create membership");

    let email_row = AccountEmail::new(
        account_id.clone(),
        email.to_string(),
        verified.then_some(now),
        now,
        now,
    )
    .expect("email");
    let email_created = AccountEmail::create_used(email_row, valence, valence::use_!(r#"**Test:** Fixture **Account Email** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .expect("create email");
    let email_id = email_created.id().cloned().expect("email id");

    account_created
        .get_mutable_used(valence, valence::use_!(r#"**Test:** Fixture **this data** access in `confirm_account_status` so the suite can arrange and assert persistence. CI and developers running the suite only."#))
        .set_primary_email(email_id.clone())
        .expect("set")
        .set_updated_at(now)
        .expect("updated")
        .commit()
        .await
        .expect("commit");
    created
        .get_mutable_used(valence, valence::use_!(r#"**Test:** Fixture **this data** access in `confirm_account_status` so the suite can arrange and assert persistence. CI and developers running the suite only."#))
        .set_primary_email(email_id)
        .expect("set")
        .set_updated_at(now)
        .expect("updated")
        .commit()
        .await
        .expect("commit");

    (user_id, account_id)
}

#[tokio::test]
async fn confirm_status_flags_email_only_happy() {
    let valence = system_valence("confirm_status_email_only").await;
    let email = "status-email-only@example.test";
    let (user, account) = seed_user_with_email(&valence, email, true).await;

    assert!(primary_email_verified(&valence, &user)
        .await
        .expect("email"));
    assert!(!primary_phone_verified(&valence, &user)
        .await
        .expect("phone"));
    assert!(!is_confirmed(&valence, &user).await.expect("confirmed"));

    let status = ConfirmAccountStatus {
        masked_email: mask_email_for_display(email),
        email_verified: true,
        masked_phone: None,
        phone_verified: false,
        confirmed: false,
    };
    assert!(status.email_verified);
    assert!(!status.phone_verified);
    assert!(!status.confirmed);
    let _ = account;
}

#[tokio::test]
async fn confirm_status_ready_then_confirm_happy() {
    let valence = system_valence("confirm_status_ready").await;
    let email = "status-ready@example.test";
    let (user, account) = seed_user_with_email(&valence, email, true).await;

    let phone = add_account_phone(&valence, &account, "+15555550999")
        .await
        .expect("add phone");
    mark_account_phone_verified(&valence, &phone)
        .await
        .expect("verify phone");
    let phone_id = phone.id().cloned().expect("phone id");
    set_account_primary_phone(&valence, &account, &phone_id)
        .await
        .expect("account primary");
    set_primary_phone(&valence, &user, &phone_id)
        .await
        .expect("user primary");

    assert!(primary_phone_verified(&valence, &user)
        .await
        .expect("phone"));
    confirm_user(&valence, &user).await.expect("confirm");
    assert!(is_confirmed(&valence, &user).await.expect("confirmed"));

    let status = ConfirmAccountStatus {
        masked_email: mask_email_for_display(email),
        email_verified: true,
        masked_phone: Some(mask_phone_for_display("+15555550999")),
        phone_verified: true,
        confirmed: true,
    };
    assert!(status.confirmed);
}

#[tokio::test]
async fn confirm_blocked_without_phone_sad() {
    let valence = system_valence("confirm_status_blocked").await;
    let (user, _) = seed_user_with_email(&valence, "blocked@example.test", true).await;
    let err = confirm_user(&valence, &user).await.expect_err("blocked");
    assert_eq!(err.reason_class(), "confirm_blocked");
}
