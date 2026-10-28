//! A host-set service user limit per owner replaces the default.
//!
//! Its own test binary: the limit is installed once per process.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

#[path = "support/service_users.rs"]
mod service_users_support;

use std::sync::Once;

use lepton_auth::service_users::{
    create_service_user, delete_service_user, NewServiceUser, ServiceUserError,
    MAX_SERVICE_USERS_PER_OWNER,
};
use lepton_identity::config::{install_service_users_per_owner, service_users_per_owner};
use lepton_identity::service_users::ServiceUserId;
use service_users_support::{install_test_gate, seed_user, stored_service_user_count};
use support::{system_valence, user_valence};

const HOST_LIMIT: usize = 2;

fn setup() {
    static ONCE: Once = Once::new();
    install_test_gate();
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
    ONCE.call_once(|| install_service_users_per_owner(HOST_LIMIT).expect("first install"));
}

const fn new_service_user(handle: &str) -> NewServiceUser<'_> {
    NewServiceUser {
        handle,
        display_name: "Limited service user",
        description: None,
    }
}

#[tokio::test]
async fn host_limit_replaces_default_sad() {
    setup();
    assert_ne!(HOST_LIMIT, MAX_SERVICE_USERS_PER_OWNER);
    assert_eq!(service_users_per_owner(), HOST_LIMIT);
    let sys = system_valence("service_users_host_limit").await;
    seed_user(&sys, "maker-limited").await;
    let owner = user_valence(&sys, "maker-limited");
    for handle in ["limited-1", "limited-2"] {
        create_service_user(&owner, new_service_user(handle))
            .await
            .expect("create below the host limit");
    }

    let err = create_service_user(&owner, new_service_user("limited-3"))
        .await
        .expect_err("over the host limit");

    assert!(
        matches!(err, ServiceUserError::QuotaReached { limit } if limit == HOST_LIMIT),
        "{err:?}"
    );
    assert_eq!(
        stored_service_user_count(&sys, "maker-limited").await,
        HOST_LIMIT
    );
}

#[tokio::test]
async fn host_limit_freed_by_delete_happy() {
    setup();
    let sys = system_valence("service_users_host_limit_freed").await;
    seed_user(&sys, "maker-freed").await;
    let owner = user_valence(&sys, "maker-freed");
    let mut ids = Vec::new();
    for handle in ["freed-1", "freed-2"] {
        let service_user = create_service_user(&owner, new_service_user(handle))
            .await
            .expect("create");
        ids.push(ServiceUserId::parse(service_user.id().expect("saved").id()).expect("id"));
    }
    delete_service_user(&owner, &ids[0]).await.expect("delete");

    create_service_user(&owner, new_service_user("freed-3"))
        .await
        .expect("a deleted service user frees its slot");
}

#[test]
fn host_limit_second_install_sad() {
    setup();
    assert!(install_service_users_per_owner(50).is_err());
    assert_eq!(service_users_per_owner(), HOST_LIMIT);
}
