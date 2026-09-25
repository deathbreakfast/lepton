//! Email verify / change promotes `Account.primary_email` (TM-E1–E3).

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

use chrono::Utc;
use lepton_auth::contacts::{
    add_account_email, mark_account_email_verified, set_account_primary_email, set_primary_email,
    ContactError,
};
use lepton_host_adapter::auth::hash_password;
use lepton_host_adapter::generated::{
    Account, AccountEmail, AccountMembership, AccountMembershipRole, AccountPlan, AccountStatus,
    User, UserStatus, UserUserType,
};
use lepton_identity::ownership::bare_id_from_record;
use support::system_valence;
use valence::{Model, RecordId};

async fn seed_owner(valence: &valence::Valence, email: &str) -> (RecordId, RecordId, RecordId) {
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
    let created = User::create(user, valence, valence::use_!(r"**Test:** Fixture **User** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only.")).await.expect("create");
    let user_id = created.id().cloned().expect("id");

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
    let account = Account::create(account, valence, valence::use_!(r"**Test:** Fixture **Account** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only.")).await.expect("account");
    let account_id = account.id().cloned().expect("id");

    let membership = AccountMembership::new(
        account_id.clone(),
        user_id.clone(),
        AccountMembershipRole::Owner,
        now,
        now,
    )
    .expect("membership");
    AccountMembership::create(membership, valence, valence::use_!(r"**Test:** Fixture **Account Membership** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("membership");

    let primary =
        AccountEmail::new(account_id.clone(), email.into(), Some(now), now, now).expect("email");
    let primary = AccountEmail::create(primary, valence, valence::use_!(r"**Test:** Fixture **Account Email** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only.")).await.expect("email");
    let primary_id = primary.id().cloned().expect("id");

    Account::get(&bare_id_from_record(&account_id), valence, valence::use_!(r"**Test:** Fixture **Account** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("get")
        .expect("account")
        .get_mutable(valence, valence::use_!(r"**Test:** Fixture **this data** access in `email_change_account_primary` so the suite can arrange and assert persistence. CI and developers running the suite only."))
        .set_primary_email(primary_id.clone())
        .expect("acct primary")
        .set_updated_at(now)
        .expect("ts")
        .commit()
        .await
        .expect("commit");

    User::get(&bare_id_from_record(&user_id), valence, valence::use_!(r"**Test:** Fixture **User** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("get")
        .expect("user")
        .get_mutable(valence, valence::use_!(r"**Test:** Fixture **this data** access in `email_change_account_primary` so the suite can arrange and assert persistence. CI and developers running the suite only."))
        .set_primary_email(primary_id.clone())
        .expect("login")
        .set_updated_at(now)
        .expect("ts")
        .commit()
        .await
        .expect("commit");

    (user_id, account_id, primary_id)
}

/// Mirrors `verify_email_token` contact promotion after a successful consume.
async fn promote_verified_email_as_primaries(
    valence: &valence::Valence,
    user: &RecordId,
    account: &RecordId,
    email: &AccountEmail,
) {
    mark_account_email_verified(valence, email)
        .await
        .expect("verify");
    let email_id = email.id().cloned().expect("id");
    set_primary_email(valence, user, &email_id)
        .await
        .expect("login primary");
    set_account_primary_email(valence, account, &email_id)
        .await
        .expect("account primary");
}

#[tokio::test]
async fn verify_email_sets_account_primary_happy() {
    let valence = system_valence("verify_change_primary").await;
    let (user, account, old_primary) = seed_owner(&valence, "old@example.test").await;

    let new_email = add_account_email(&valence, &account, "new@example.test")
        .await
        .expect("add");
    promote_verified_email_as_primaries(&valence, &user, &account, &new_email).await;
    let new_id = new_email.id().cloned().expect("id");

    let acct = Account::get(&bare_id_from_record(&account), &valence, valence::use_!(r"**Test:** Fixture **Account** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("get")
        .expect("account");
    let user_row = User::get(&bare_id_from_record(&user), &valence, valence::use_!(r"**Test:** Fixture **User** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("get")
        .expect("user");
    assert_eq!(
        bare_id_from_record(acct.primary_email().expect("acct")),
        bare_id_from_record(&new_id)
    );
    assert_eq!(
        bare_id_from_record(user_row.primary_email().expect("login")),
        bare_id_from_record(&new_id)
    );
    assert_ne!(
        bare_id_from_record(&new_id),
        bare_id_from_record(&old_primary)
    );
}

#[tokio::test]
async fn verify_signup_email_sets_account_primary_happy() {
    let valence = system_valence("verify_signup_primary").await;
    let now = Utc::now();
    let user = User::new(
        Some(UserUserType::Person),
        Some(hash_password("CorrectHorseBattery1!").expect("hash")),
        Some(UserStatus::PendingVerification),
        None,
        None,
        None,
        None,
        None,
        now,
        now,
    )
    .expect("user");
    let user = User::create(user, &valence, valence::use_!(r"**Test:** Fixture **User** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only.")).await.expect("create");
    let user_id = user.id().cloned().expect("id");

    let account = Account::new(
        "signup@example.test".into(),
        user_id.clone(),
        Some(AccountPlan::Free),
        Some(AccountStatus::Active),
        None,
        None,
        now,
        now,
    )
    .expect("account");
    let account = Account::create(account, &valence, valence::use_!(r"**Test:** Fixture **Account** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only.")).await.expect("account");
    let account_id = account.id().cloned().expect("id");

    AccountMembership::create(
        AccountMembership::new(
            account_id.clone(),
            user_id.clone(),
            AccountMembershipRole::Owner,
            now,
            now,
        )
        .expect("m"),
        &valence,
        valence::use_!(r"**Test:** Fixture **Account Membership** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."),
    )
    .await
    .expect("membership");

    let email = add_account_email(&valence, &account_id, "signup@example.test")
        .await
        .expect("add");
    // Signup leaves unverified until token verify — then both primaries set.
    promote_verified_email_as_primaries(&valence, &user_id, &account_id, &email).await;
    let email_id = email.id().cloned().expect("id");

    let acct = Account::get(&bare_id_from_record(&account_id), &valence, valence::use_!(r"**Test:** Fixture **Account** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("get")
        .expect("account");
    let user_row = User::get(&bare_id_from_record(&user_id), &valence, valence::use_!(r"**Test:** Fixture **User** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("get")
        .expect("user");
    assert_eq!(
        bare_id_from_record(acct.primary_email().expect("acct")),
        bare_id_from_record(&email_id)
    );
    assert_eq!(
        bare_id_from_record(user_row.primary_email().expect("login")),
        bare_id_from_record(&email_id)
    );
}

#[tokio::test]
async fn change_email_unverified_not_account_primary_sad() {
    let valence = system_valence("change_unverified").await;
    let (_user, account, old_primary) = seed_owner(&valence, "keep@example.test").await;

    let pending = add_account_email(&valence, &account, "pending@example.test")
        .await
        .expect("add");
    let pending_id = pending.id().cloned().expect("id");

    let err = set_account_primary_email(&valence, &account, &pending_id)
        .await
        .expect_err("unverified");
    assert!(matches!(err, ContactError::Unverified));

    let acct = Account::get(&bare_id_from_record(&account), &valence, valence::use_!(r"**Test:** Fixture **Account** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("get")
        .expect("account");
    assert_eq!(
        bare_id_from_record(acct.primary_email().expect("unchanged")),
        bare_id_from_record(&old_primary)
    );
}
