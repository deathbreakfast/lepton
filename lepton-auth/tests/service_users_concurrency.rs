//! Two creates racing for the same owner cannot exceed the quota or share a handle.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

#[path = "support/service_users.rs"]
mod service_users_support;

use lepton_auth::service_users::{
    create_service_user, NewServiceUser, ServiceUserError, MAX_SERVICE_USERS_PER_OWNER,
};
use service_users_support::{install_test_gate, seed_user, stored_service_user_count};
use support::{system_valence, user_valence};
use valence::Valence;

fn setup() {
    install_test_gate();
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
}

const fn profile(handle: &str) -> NewServiceUser<'_> {
    NewServiceUser {
        handle,
        display_name: "Racer",
        description: None,
    }
}

/// Create `count` service users for `owner`, one handle each.
async fn fill(owner: &Valence, count: usize) {
    for n in 0..count {
        create_service_user(owner, profile(&format!("seat-{n}")))
            .await
            .expect("create below the limit");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_create_respects_quota() {
    setup();
    let sys = system_valence("service_users_race_quota").await;
    seed_user(&sys, "maker-race").await;
    let owner = user_valence(&sys, "maker-race");
    // One slot left: two racers contend for it.
    fill(&owner, MAX_SERVICE_USERS_PER_OWNER - 1).await;

    let a = user_valence(&sys, "maker-race");
    let b = user_valence(&sys, "maker-race");
    let ta = tokio::spawn(async move { create_service_user(&a, profile("race-a")).await });
    let tb = tokio::spawn(async move { create_service_user(&b, profile("race-b")).await });
    let ra = ta.await.expect("task a");
    let rb = tb.await.expect("task b");

    let winners = [&ra, &rb].iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        winners, 1,
        "exactly one wins the last slot: {ra:?} / {rb:?}"
    );
    let loser = [ra, rb]
        .into_iter()
        .find_map(Result::err)
        .expect("one loses");
    assert!(
        matches!(loser, ServiceUserError::QuotaReached { limit } if limit == MAX_SERVICE_USERS_PER_OWNER),
        "{loser:?}"
    );
    assert_eq!(
        stored_service_user_count(&sys, "maker-race").await,
        MAX_SERVICE_USERS_PER_OWNER,
        "the quota is never exceeded"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_create_rejects_shared_handle() {
    setup();
    let sys = system_valence("service_users_race_handle").await;
    seed_user(&sys, "maker-dup").await;

    let a = user_valence(&sys, "maker-dup");
    let b = user_valence(&sys, "maker-dup");
    let ta = tokio::spawn(async move { create_service_user(&a, profile("dup")).await });
    let tb = tokio::spawn(async move { create_service_user(&b, profile("dup")).await });
    let ra = ta.await.expect("task a");
    let rb = tb.await.expect("task b");

    let winners = [&ra, &rb].iter().filter(|r| r.is_ok()).count();
    assert_eq!(winners, 1, "exactly one claims the handle: {ra:?} / {rb:?}");
    let loser = [ra, rb]
        .into_iter()
        .find_map(Result::err)
        .expect("one loses");
    assert!(
        matches!(loser, ServiceUserError::HandleTaken { .. }),
        "{loser:?}"
    );
    assert_eq!(
        stored_service_user_count(&sys, "maker-dup").await,
        1,
        "only one service user holds the handle"
    );
}
