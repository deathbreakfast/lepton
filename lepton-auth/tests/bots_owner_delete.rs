//! Deleting the owner's user deletes their bots and nobody else's (TM-B9).

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

#[path = "support/bots.rs"]
mod bots_support;

use bots_support::{install_test_gate, seed_bot, stored_bot, stored_bot_count};
use lepton_auth::identity_delete::delete_user;
use valence::RecordId;

use support::system_valence;

#[tokio::test]
async fn delete_user_removes_bots_happy() {
    install_test_gate();
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
    let sys = system_valence("bots_owner_delete").await;
    let (_, first, _) = seed_bot(&sys, "maker-alice", "first-bot").await;
    let (alice, _, _) = seed_bot(&sys, "maker-alice", "second-bot").await;
    let _ = alice;
    let (_, bobs, _) = seed_bot(&sys, "maker-bob", "bobs-bot").await;
    assert_eq!(stored_bot_count(&sys, "maker-alice").await, 2);

    delete_user(&sys, &RecordId::new("user", "maker-alice"))
        .await
        .expect("erase alice");

    assert_eq!(stored_bot_count(&sys, "maker-alice").await, 0);
    assert!(
        stored_bot(&sys, &first).await.is_none(),
        "row physically removed"
    );
    assert!(
        stored_bot(&sys, &bobs).await.is_some(),
        "other owner's bot stays"
    );
    assert_eq!(stored_bot_count(&sys, "maker-bob").await, 1);
}
