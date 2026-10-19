//! Per-owner service user limit (`lepton_service_user_quota_01`).

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

#[path = "support/service_users.rs"]
mod service_users_support;

use lepton_auth::service_users::{
    create_service_user, delete_service_user, suspend_service_user, NewServiceUser,
    ServiceUserError, MAX_SERVICE_USERS_PER_OWNER,
};
use lepton_identity::service_users::ServiceUserId;
use service_users_support::{install_test_gate, seed_user, stored_service_user_count};
use support::{system_valence, user_valence};
use valence::Valence;

fn setup() {
    install_test_gate();
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
}

/// Create `count` service users for the caller and return their ids.
async fn fill(v: &Valence, prefix: &str, count: usize) -> Vec<ServiceUserId> {
    let mut ids = Vec::with_capacity(count);
    for n in 0..count {
        let handle = format!("{prefix}-{n}");
        let service_user = create_service_user(
            v,
            NewServiceUser {
                handle: &handle,
                display_name: "Quota service user",
                description: None,
            },
        )
        .await
        .expect("create below the limit");
        ids.push(
            ServiceUserId::parse(service_user.id().expect("saved").id()).expect("service user id"),
        );
    }
    ids
}

const fn one_more(handle: &str) -> NewServiceUser<'_> {
    NewServiceUser {
        handle,
        display_name: "One too many",
        description: None,
    }
}

#[tokio::test]
async fn tm_service_user_quota_reached_sad() {
    setup();
    let sys = system_valence("service_users_quota_reached").await;
    seed_user(&sys, "maker-quota").await;
    let owner = user_valence(&sys, "maker-quota");
    fill(&owner, "full", MAX_SERVICE_USERS_PER_OWNER).await;

    let err = create_service_user(&owner, one_more("extra"))
        .await
        .expect_err("over the limit");

    assert!(
        matches!(err, ServiceUserError::QuotaReached { limit } if limit == MAX_SERVICE_USERS_PER_OWNER),
        "{err:?}"
    );
    assert_eq!(err.reason_class(), "quota");
    assert_eq!(
        stored_service_user_count(&sys, "maker-quota").await,
        MAX_SERVICE_USERS_PER_OWNER
    );
}

#[tokio::test]
async fn tm_service_user_quota_counts_suspended_sad() {
    setup();
    let sys = system_valence("service_users_quota_suspended").await;
    seed_user(&sys, "maker-paused").await;
    let owner = user_valence(&sys, "maker-paused");
    let ids = fill(&owner, "paused", MAX_SERVICE_USERS_PER_OWNER).await;
    suspend_service_user(&owner, &ids[0])
        .await
        .expect("suspend");

    let err = create_service_user(&owner, one_more("extra"))
        .await
        .expect_err("suspended service users still count");

    assert!(
        matches!(err, ServiceUserError::QuotaReached { .. }),
        "{err:?}"
    );
    assert_eq!(
        stored_service_user_count(&sys, "maker-paused").await,
        MAX_SERVICE_USERS_PER_OWNER
    );
}

#[tokio::test]
async fn tm_service_user_quota_ignores_deleted_happy() {
    setup();
    let sys = system_valence("service_users_quota_deleted").await;
    seed_user(&sys, "maker-freed").await;
    let owner = user_valence(&sys, "maker-freed");
    let ids = fill(&owner, "freed", MAX_SERVICE_USERS_PER_OWNER).await;
    delete_service_user(&owner, &ids[0]).await.expect("delete");

    let service_user = create_service_user(&owner, one_more("replacement"))
        .await
        .expect("a deleted service user frees its slot");

    assert_eq!(service_user.handle(), "replacement");
}

#[tokio::test]
async fn tm_service_user_quota_is_per_owner_happy() {
    setup();
    let sys = system_valence("service_users_quota_per_owner").await;
    seed_user(&sys, "maker-busy").await;
    seed_user(&sys, "maker-other").await;
    let busy = user_valence(&sys, "maker-busy");
    let other = user_valence(&sys, "maker-other");
    fill(&busy, "busy", MAX_SERVICE_USERS_PER_OWNER).await;

    create_service_user(&other, one_more("other"))
        .await
        .expect("another owner is not affected");

    assert_eq!(stored_service_user_count(&sys, "maker-other").await, 1);
}
