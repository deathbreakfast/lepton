//! Deleting the owner's user deletes their service users and nobody else's (TM-B9).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use crate::support;

use crate::service_users_support;

use chrono::Utc;
use lepton_auth::identity_delete::{delete_user, erase_account, IdentityDeleteError};
use lepton_host_adapter::generated::{
    Account, AccountMembership, AccountMembershipRole, AccountPlan, AccountStatus,
};
use service_users_support::{
    install_test_gate, seed_service_user, stored_service_user, stored_service_user_count,
};
use valence::{Model, RecordId, Valence};

use support::system_valence;

#[tokio::test]
async fn delete_user_removes_service_users_happy() {
    install_test_gate();
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
    let sys = system_valence("service_users_owner_delete").await;
    let (_, first, _) = seed_service_user(&sys, "maker-alice", "first").await;
    let (alice, _, _) = seed_service_user(&sys, "maker-alice", "second").await;
    let _ = alice;
    let (_, bobs, _) = seed_service_user(&sys, "maker-bob", "bobs").await;
    assert_eq!(stored_service_user_count(&sys, "maker-alice").await, 2);

    delete_user(&sys, &RecordId::new("user", "maker-alice"))
        .await
        .expect("erase alice");

    assert_eq!(stored_service_user_count(&sys, "maker-alice").await, 0);
    assert!(
        stored_service_user(&sys, &first).await.is_none(),
        "row physically removed"
    );
    assert!(
        stored_service_user(&sys, &bobs).await.is_some(),
        "other owner's service user stays"
    );
    assert_eq!(stored_service_user_count(&sys, "maker-bob").await, 1);
}

/// Erasing the owner cascades through the `user` connection and removes the
/// service user row the owner owns (`on_delete: Cascade`).
#[tokio::test]
async fn owner_erasure_cascades_service_user_rows() {
    install_test_gate();
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
    let sys = system_valence("service_users_owner_cascade").await;
    let (_, owned, _) = seed_service_user(&sys, "maker-alice", "downstream").await;
    assert!(
        stored_service_user(&sys, &owned).await.is_some(),
        "the service user row exists before erasure"
    );

    delete_user(&sys, &RecordId::new("user", "maker-alice"))
        .await
        .expect("erase owner");

    assert!(
        stored_service_user(&sys, &owned).await.is_none(),
        "the downstream service user row is removed with its owner"
    );
    assert_eq!(stored_service_user_count(&sys, "maker-alice").await, 0);
}

/// **Test:** an account owned by `members[0]` with every entry in `members` as a member, created through System fixtures.
async fn seed_account_with_members(sys: &Valence, name: &str, members: &[&str]) -> RecordId {
    let now = Utc::now();
    let owner = RecordId::new("user", members[0]);
    let account = Account::new(
        name.to_string(),
        owner,
        Some(AccountPlan::Free),
        Some(AccountStatus::Active),
        None,
        None,
        now,
        now,
    )
    .expect("account");
    let created = Account::create(account, sys, valence::use_!(r"**Test:** Fixture **Account** save for `service_users` tests so the suite can erase an account that has service-user owners. CI and developers running the suite only."))
        .await
        .expect("create account");
    let account_id = created.id().cloned().expect("account id");
    for member in members {
        let membership = AccountMembership::new(
            account_id.clone(),
            RecordId::new("user", *member),
            AccountMembershipRole::Owner,
            now,
            now,
        )
        .expect("membership");
        AccountMembership::create(membership, sys, valence::use_!(r"**Test:** Fixture **Account Membership** save for `service_users` tests so the suite can erase an account that has service-user owners. CI and developers running the suite only."))
            .await
            .expect("create membership");
    }
    account_id
}

/// Erasing an account deletes every member user, and with them their service users.
#[tokio::test]
async fn erase_account_removes_member_service_users_happy() {
    install_test_gate();
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
    let sys = system_valence("service_users_erase_account").await;
    let (_, first, _) = seed_service_user(&sys, "maker-erase-a", "erase-first").await;
    let (_, second, _) = seed_service_user(&sys, "maker-erase-a", "erase-second").await;
    let (_, peer, _) = seed_service_user(&sys, "maker-erase-b", "erase-peer").await;
    let (_, bystander, _) = seed_service_user(&sys, "maker-erase-c", "erase-bystander").await;
    let account =
        seed_account_with_members(&sys, "erase-bots", &["maker-erase-a", "maker-erase-b"]).await;

    erase_account(&sys, &account).await.expect("erase account");

    for gone in [&first, &second, &peer] {
        assert!(
            stored_service_user(&sys, gone).await.is_none(),
            "member's service user row removed"
        );
    }
    assert_eq!(stored_service_user_count(&sys, "maker-erase-a").await, 0);
    assert_eq!(stored_service_user_count(&sys, "maker-erase-b").await, 0);
    assert!(
        stored_service_user(&sys, &bystander).await.is_some(),
        "a non-member's service user stays"
    );
    assert_eq!(stored_service_user_count(&sys, "maker-erase-c").await, 1);
}

#[tokio::test]
async fn erase_missing_account_keeps_service_users_sad() {
    install_test_gate();
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
    let sys = system_valence("service_users_erase_missing").await;
    let (_, kept, _) = seed_service_user(&sys, "maker-erase-missing", "erase-kept").await;

    let err = erase_account(&sys, &RecordId::new("account", "no-such-account"))
        .await
        .expect_err("missing account");

    assert!(matches!(err, IdentityDeleteError::AccountMissing));
    assert!(stored_service_user(&sys, &kept).await.is_some());
}
