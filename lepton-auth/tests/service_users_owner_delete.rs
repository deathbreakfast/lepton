//! Deleting the owner's user deletes their service users and nobody else's (TM-B9).

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

#[path = "support/service_users.rs"]
mod service_users_support;

use lepton_auth::identity_delete::delete_user;
use service_users_support::{
    install_test_gate, seed_service_user, stored_service_user, stored_service_user_count,
};
use valence::RecordId;

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
