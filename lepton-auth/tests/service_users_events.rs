//! Service user lifecycle changes publish one Photon event each, with ids only.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

#[path = "support/service_users.rs"]
mod service_users_support;

use lepton_auth::events::test_support::{take_service_user_published, ServiceUserPublish};
use lepton_auth::events::ServiceUserLifecycleEvent;
use lepton_auth::service_users::{
    create_service_user, delete_service_user, resume_service_user, suspend_service_user,
    update_service_user, NewServiceUser, ServiceUserProfileUpdate,
};
use service_users_support::{install_test_gate, seed_service_user, seed_user};
use support::{system_valence, user_valence};

fn setup() {
    install_test_gate();
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
}

/// Captured publishes for `owner`. The capture is process-wide and tests run in
/// parallel, so each test reads only its own owner's events.
fn published_for(owner: &str, log: &mut Vec<ServiceUserPublish>) -> Vec<ServiceUserPublish> {
    log.extend(take_service_user_published());
    let (mine, rest): (Vec<_>, Vec<_>) = log.drain(..).partition(|(o, _, _)| o == owner);
    *log = rest;
    mine
}

#[tokio::test]
async fn one_event_per_lifecycle_change_happy() {
    setup();
    let sys = system_valence("service_users_events").await;
    let owner = "maker-events";
    let (owner_v, id, _) = seed_service_user(&sys, owner, "events-agent").await;
    suspend_service_user(&owner_v, &id).await.expect("suspend");
    resume_service_user(&owner_v, &id).await.expect("resume");
    update_service_user(
        &owner_v,
        &id,
        ServiceUserProfileUpdate {
            display_name: Some("Renamed"),
            description: None,
        },
    )
    .await
    .expect("edit");
    delete_service_user(&owner_v, &id).await.expect("delete");

    let mut log = Vec::new();
    let events = published_for(owner, &mut log);

    let expected: Vec<ServiceUserPublish> = [
        ServiceUserLifecycleEvent::Created,
        ServiceUserLifecycleEvent::Suspended,
        ServiceUserLifecycleEvent::Resumed,
        ServiceUserLifecycleEvent::Deleted,
    ]
    .into_iter()
    .map(|event| (owner.to_string(), id.as_str().to_string(), event))
    .collect();
    assert_eq!(events, expected);
}

#[tokio::test]
async fn refused_changes_publish_nothing_sad() {
    setup();
    let sys = system_valence("service_users_events_refused").await;
    let owner = "maker-events-refused";
    let (owner_v, id, _) = seed_service_user(&sys, owner, "refused-agent").await;
    seed_user(&sys, "maker-events-peer").await;
    let peer = user_valence(&sys, "maker-events-peer");

    resume_service_user(&owner_v, &id)
        .await
        .expect_err("already active");
    suspend_service_user(&peer, &id).await.expect_err("peer");
    delete_service_user(&peer, &id).await.expect_err("peer");
    create_service_user(
        &owner_v,
        NewServiceUser {
            handle: "refused-agent",
            display_name: "Clash",
            description: None,
        },
    )
    .await
    .expect_err("handle taken");

    let mut log = Vec::new();
    let events = published_for(owner, &mut log);
    assert_eq!(
        events,
        [(
            owner.to_string(),
            id.as_str().to_string(),
            ServiceUserLifecycleEvent::Created
        )]
    );
    assert!(published_for("maker-events-peer", &mut log).is_empty());
}
