//! Service user lifecycle: create, handle clashes, edit, suspend, resume, delete
//! (TM-B1, TM-B3, TM-B4 gate error, TM-B5 creator, TM-B7).

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

#[path = "support/service_users.rs"]
mod service_users_support;

use lepton_auth::identity_delete::delete_user;
use lepton_auth::service_users::{
    create_service_user, delete_service_user, get_service_user, list_my_service_users,
    resume_service_user, suggest_service_user_handle, suspend_service_user, update_service_user,
    NewServiceUser, ServiceUserError, ServiceUserProfileUpdate,
};
use lepton_host_adapter::generated::{ServiceUserAccountOwnerKind, ServiceUserAccountStatus};
use service_users_support::{
    install_test_gate, seed_service_user, seed_user, stored_service_user, stored_service_user_count,
};
use support::{system_valence, user_valence};
use valence::RecordId;

fn setup() {
    install_test_gate();
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
}

const fn new_service_user(handle: &str) -> NewServiceUser<'_> {
    NewServiceUser {
        handle,
        display_name: "Spectra agent",
        description: Some("Reads metrics"),
    }
}

#[tokio::test]
async fn create_service_user_creator_happy() {
    setup();
    let sys = system_valence("service_users_create").await;
    seed_user(&sys, "maker-alice").await;
    let alice = user_valence(&sys, "maker-alice");

    let service_user = create_service_user(&alice, new_service_user("Spectra-Agent"))
        .await
        .expect("create");

    assert_eq!(service_user.handle(), "spectra-agent");
    assert_eq!(service_user.handle_key(), "spectraagent");
    assert_eq!(service_user.display_name(), "Spectra agent");
    assert_eq!(
        service_user.description().map(String::as_str),
        Some("Reads metrics")
    );
    assert_eq!(service_user.status(), &ServiceUserAccountStatus::Active);
    assert_eq!(
        service_user.owner_kind(),
        &ServiceUserAccountOwnerKind::User
    );
    assert!(service_user.suspended_at().is_none());
    assert_eq!(service_user.created_at(), service_user.updated_at());
    let owner = service_user.user().expect("owner").id().to_string();
    assert!(owner.ends_with("maker-alice"), "{owner}");
    let creator = service_user.created_by().expect("creator").id().to_string();
    assert!(creator.ends_with("maker-alice"), "{creator}");
    assert_eq!(stored_service_user_count(&sys, "maker-alice").await, 1);
}

#[tokio::test]
async fn service_user_schema_round_trip_happy() {
    setup();
    let sys = system_valence("service_users_round_trip").await;
    let (alice, id, created) = seed_service_user(&sys, "maker-alice", "round-trip").await;

    let loaded = get_service_user(&alice, &id).await.expect("owner reads");
    assert_eq!(loaded.handle(), created.handle());
    assert_eq!(loaded.display_name(), created.display_name());
    assert_eq!(loaded.status(), &ServiceUserAccountStatus::Active);
    assert_eq!(
        loaded.created_at().timestamp(),
        created.created_at().timestamp()
    );
    let raw = stored_service_user(&sys, &id).await.expect("stored");
    assert_eq!(raw["status"], "active");
    assert_eq!(raw["owner_kind"], "user");
}

#[tokio::test]
async fn create_service_user_handle_clash_returns_suggestion_sad() {
    setup();
    let sys = system_valence("service_users_clash").await;
    let (alice, _, _) = seed_service_user(&sys, "maker-alice", "spectra-agent").await;

    let err = create_service_user(&alice, new_service_user("SpectraAgent"))
        .await
        .expect_err("clash");
    let ServiceUserError::HandleTaken { suggestion } = err else {
        panic!("expected HandleTaken, got {err:?}");
    };
    assert_eq!(suggestion.expect("suggestion").as_str(), "spectraagent-2");
    assert_eq!(
        stored_service_user_count(&sys, "maker-alice").await,
        1,
        "no second row"
    );

    create_service_user(&alice, new_service_user("spectraagent-2"))
        .await
        .expect("suggestion is free");
}

#[tokio::test]
async fn create_service_user_handle_clash_across_owners_sad() {
    setup();
    let sys = system_valence("service_users_clash_owners").await;
    seed_service_user(&sys, "maker-alice", "shared").await;
    seed_user(&sys, "maker-bob").await;
    let bob = user_valence(&sys, "maker-bob");

    let err = create_service_user(&bob, new_service_user("shared"))
        .await
        .expect_err("clash");
    assert!(
        matches!(
            err,
            ServiceUserError::HandleTaken {
                suggestion: Some(_)
            }
        ),
        "{err:?}"
    );
    assert_eq!(stored_service_user_count(&sys, "maker-bob").await, 0);
}

#[tokio::test]
async fn suggest_service_user_handle_happy() {
    setup();
    let sys = system_valence("service_users_suggest").await;
    let (alice, _, _) = seed_service_user(&sys, "maker-alice", "spectra").await;

    let taken = suggest_service_user_handle(&alice, "Spectra")
        .await
        .expect("suggest");
    assert_eq!(taken.as_str(), "spectra-2");
    let free = suggest_service_user_handle(&alice, "Magnon reader")
        .await
        .expect("suggest");
    assert_eq!(free.as_str(), "magnon-reader");
}

#[tokio::test]
async fn create_service_user_invalid_input_sad() {
    setup();
    let sys = system_valence("service_users_invalid").await;
    seed_user(&sys, "maker-alice").await;
    let alice = user_valence(&sys, "maker-alice");

    let err = create_service_user(&alice, new_service_user("se@n"))
        .await
        .expect_err("invalid char");
    assert_eq!(err.reason_class(), "handle");
    let err = create_service_user(&alice, new_service_user("support"))
        .await
        .expect_err("reserved");
    assert_eq!(err.reason_class(), "handle");
    let err = create_service_user(
        &alice,
        NewServiceUser {
            handle: "ok-agent",
            display_name: "  ",
            description: None,
        },
    )
    .await
    .expect_err("empty name");
    assert!(matches!(
        err,
        ServiceUserError::InvalidProfile {
            field: "display_name"
        }
    ));
    assert!(
        !err.to_string().contains("ok-agent"),
        "no input echo: {err}"
    );
    assert_eq!(stored_service_user_count(&sys, "maker-alice").await, 0);
}

#[tokio::test]
async fn create_service_user_not_permitted_sad() {
    setup();
    let sys = system_valence("service_users_not_permitted").await;
    seed_user(&sys, "plain-carol").await;
    let carol = user_valence(&sys, "plain-carol");

    let err = create_service_user(&carol, new_service_user("carol"))
        .await
        .expect_err("gate says no");
    assert!(
        matches!(err, ServiceUserError::CreateNotPermitted),
        "{err:?}"
    );
    assert_eq!(stored_service_user_count(&sys, "plain-carol").await, 0);
}

#[tokio::test]
async fn gate_error_maps_to_gate_sad() {
    setup();
    let sys = system_valence("service_users_gate_error").await;
    seed_user(&sys, "gatefail-dan").await;
    let dan = user_valence(&sys, "gatefail-dan");

    let err = create_service_user(&dan, new_service_user("dan"))
        .await
        .expect_err("gate fails");
    assert!(
        matches!(err, ServiceUserError::Gate(e) if e.reason_class == "store"),
        "{err:?}"
    );
    assert_eq!(stored_service_user_count(&sys, "gatefail-dan").await, 0);
}

#[tokio::test]
async fn update_service_user_owner_happy() {
    setup();
    let sys = system_valence("service_users_update").await;
    let (alice, id, created) = seed_service_user(&sys, "maker-alice", "edit-me").await;

    let updated = update_service_user(
        &alice,
        &id,
        ServiceUserProfileUpdate {
            display_name: Some(" Spectra reader "),
            description: Some(None),
        },
    )
    .await
    .expect("owner edits");

    assert_eq!(updated.display_name(), "Spectra reader");
    assert!(updated.description().is_none());
    assert_eq!(updated.handle(), created.handle());
    assert_eq!(updated.status(), &ServiceUserAccountStatus::Active);
    assert!(updated.updated_at() >= created.updated_at());
    let raw = stored_service_user(&sys, &id).await.expect("stored");
    assert_eq!(raw["display_name"], "Spectra reader");
    assert_eq!(raw["handle"], "edit-me");
}

#[tokio::test]
async fn update_service_user_invalid_profile_sad() {
    setup();
    let sys = system_valence("service_users_update_invalid").await;
    let (alice, id, _) = seed_service_user(&sys, "maker-alice", "edit-bad").await;

    let long = "x".repeat(501);
    let err = update_service_user(
        &alice,
        &id,
        ServiceUserProfileUpdate {
            display_name: None,
            description: Some(Some(&long)),
        },
    )
    .await
    .expect_err("too long");
    assert!(matches!(
        err,
        ServiceUserError::InvalidProfile {
            field: "description"
        }
    ));
    let raw = stored_service_user(&sys, &id).await.expect("stored");
    assert_eq!(raw["description"], "Fixture", "unchanged");
}

#[tokio::test]
async fn suspend_resume_owner_happy() {
    setup();
    let sys = system_valence("service_users_suspend").await;
    let (alice, id, _) = seed_service_user(&sys, "maker-alice", "pause").await;

    let suspended = suspend_service_user(&alice, &id).await.expect("suspend");
    assert_eq!(suspended.status(), &ServiceUserAccountStatus::Suspended);
    assert!(suspended.suspended_at().is_some());
    assert_eq!(
        stored_service_user(&sys, &id).await.expect("row")["status"],
        "suspended"
    );

    let resumed = resume_service_user(&alice, &id).await.expect("resume");
    assert_eq!(resumed.status(), &ServiceUserAccountStatus::Active);
    assert!(resumed.suspended_at().is_none());
    assert_eq!(
        stored_service_user(&sys, &id).await.expect("row")["status"],
        "active"
    );
}

#[tokio::test]
async fn suspend_twice_sad() {
    setup();
    let sys = system_valence("service_users_suspend_twice").await;
    let (alice, id, _) = seed_service_user(&sys, "maker-alice", "twice").await;
    suspend_service_user(&alice, &id)
        .await
        .expect("first suspend");
    let before = stored_service_user(&sys, &id).await.expect("row");

    let err = suspend_service_user(&alice, &id)
        .await
        .expect_err("already suspended");
    assert!(matches!(
        err,
        ServiceUserError::InvalidTransition {
            from: ServiceUserAccountStatus::Suspended
        }
    ));
    assert_eq!(
        stored_service_user(&sys, &id).await.expect("row")["updated_at"],
        before["updated_at"]
    );

    let err = resume_service_user(&alice, &id).await;
    assert!(err.is_ok());
    let err = resume_service_user(&alice, &id)
        .await
        .expect_err("already active");
    assert!(matches!(
        err,
        ServiceUserError::InvalidTransition {
            from: ServiceUserAccountStatus::Active
        }
    ));
}

#[tokio::test]
async fn delete_service_user_owner_happy() {
    setup();
    let sys = system_valence("service_users_delete").await;
    let (alice, id, _) = seed_service_user(&sys, "maker-alice", "gone").await;
    let (_, keep, _) = seed_service_user(&sys, "maker-alice", "kept").await;

    delete_service_user(&alice, &id)
        .await
        .expect("owner deletes");

    assert!(matches!(
        get_service_user(&alice, &id).await,
        Err(ServiceUserError::NotFound)
    ));
    let listed = list_my_service_users(&alice).await.expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].handle(), "kept");
    get_service_user(&alice, &keep)
        .await
        .expect("other service user untouched");
}

#[tokio::test]
async fn handle_unique_after_delete_reusable() {
    setup();
    let sys = system_valence("service_users_handle_reuse").await;
    // Alice takes the handle, then her account is erased, which purges the row.
    let (_, id, _) = seed_service_user(&sys, "maker-alice", "reused").await;
    delete_user(&sys, &RecordId::new("user", "maker-alice"))
        .await
        .expect("erase owner, purging the service user row");
    assert!(
        stored_service_user(&sys, &id).await.is_none(),
        "the row is gone, so its handle is free"
    );

    // With the row purged, the handle is free for a new owner to claim.
    seed_user(&sys, "maker-bob").await;
    let bob = user_valence(&sys, "maker-bob");
    let again = create_service_user(&bob, new_service_user("reused"))
        .await
        .expect("a purged handle is reusable");
    assert_eq!(again.handle(), "reused");
}

#[tokio::test]
async fn super_user_manage_any_happy() {
    setup();
    let sys = system_valence("service_users_super").await;
    let (_, id, _) = seed_service_user(&sys, "maker-alice", "managed").await;
    seed_user(&sys, "super-sam").await;
    let sam = user_valence(&sys, "super-sam");

    get_service_user(&sam, &id).await.expect("super user reads");
    let suspended = suspend_service_user(&sam, &id)
        .await
        .expect("super user suspends");
    assert_eq!(suspended.status(), &ServiceUserAccountStatus::Suspended);
    assert!(
        suspended
            .user()
            .expect("owner")
            .id()
            .ends_with("maker-alice"),
        "owner unchanged"
    );
    delete_service_user(&sam, &id)
        .await
        .expect("super user deletes");
    let alice = user_valence(&sys, "maker-alice");
    assert!(matches!(
        get_service_user(&alice, &id).await,
        Err(ServiceUserError::NotFound)
    ));
}

#[tokio::test]
async fn list_my_service_users_happy() {
    setup();
    let sys = system_valence("service_users_list").await;
    let (alice, _, _) = seed_service_user(&sys, "maker-alice", "first").await;
    create_service_user(&alice, new_service_user("second"))
        .await
        .expect("second");

    let handles: Vec<String> = list_my_service_users(&alice)
        .await
        .expect("list")
        .iter()
        .map(|b| b.handle().clone())
        .collect();
    assert_eq!(handles, ["first", "second"]);
}
