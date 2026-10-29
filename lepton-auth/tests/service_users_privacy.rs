//! Service user privacy: the create gate holds at the Valence layer, owners cannot be
//! changed, peers see nothing, and service users never manage themselves
//! (TM-B5, TM-B6, TM-B8).

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

#[path = "support/service_users.rs"]
mod service_users_support;

use chrono::Utc;
use lepton_auth::service_users::{
    create_service_user, delete_service_user, get_service_user, list_all_service_users,
    list_my_service_users, suspend_service_user, update_service_user, NewServiceUser,
    ServiceUserError, ServiceUserProfileUpdate,
};
use lepton_host_adapter::generated::{
    ServiceUserAccount, ServiceUserAccountOwnerKind, ServiceUserAccountStatus,
};
use lepton_identity::service_users::ServiceUserId;
use service_users_support::{
    install_test_gate, seed_service_user, seed_user, stored_service_user, stored_service_user_count,
};
use valence::{Actor, Model, RecordId, Valence};

use support::{system_valence, user_valence};

fn setup() {
    install_test_gate();
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
}

fn row(owner: &str, creator: &str, handle: &str) -> ServiceUserAccount {
    let now = Utc::now();
    ServiceUserAccount::new(
        Some(RecordId::new("user", owner)),
        ServiceUserAccountOwnerKind::User,
        Some(RecordId::new("user", creator)),
        handle.to_string(),
        handle.replace('-', ""),
        "Direct".to_string(),
        None,
        ServiceUserAccountStatus::Active,
        None,
        now,
        now,
    )
    .expect("row")
}

async fn direct_upsert(
    v: &Valence,
    id: &ServiceUserId,
    data: ServiceUserAccount,
) -> valence::Result<ServiceUserAccount> {
    ServiceUserAccount::upsert(id.as_str(), data, v, valence::use_!(r"**Test:** Direct **service user** save for `service_users_privacy` so the suite can prove privacy rules hold without the service layer. CI and developers running the suite only.")).await
}

// --- TM-B5: create gate enforced in Valence --------------------------------

#[tokio::test]
async fn service_user_create_direct_model_non_creator_sad() {
    setup();
    let sys = system_valence("service_users_direct_create").await;
    seed_user(&sys, "plain-carol").await;
    let carol = user_valence(&sys, "plain-carol");
    let id = ServiceUserId::new_v4();

    let err = direct_upsert(&carol, &id, row("plain-carol", "plain-carol", "carol"))
        .await
        .expect_err("gate refuses at the model layer");
    assert!(matches!(err, valence::Error::Privacy(_)), "{err:?}");
    assert!(stored_service_user(&sys, &id).await.is_none());
}

#[tokio::test]
async fn service_user_create_direct_model_creator_happy() {
    setup();
    let sys = system_valence("service_users_direct_create_ok").await;
    seed_user(&sys, "maker-alice").await;
    let alice = user_valence(&sys, "maker-alice");
    let id = ServiceUserId::new_v4();

    direct_upsert(&alice, &id, row("maker-alice", "maker-alice", "direct"))
        .await
        .expect("creator passes the rule");
    assert!(stored_service_user(&sys, &id).await.is_some());
}

#[tokio::test]
async fn service_user_create_for_other_owner_sad() {
    setup();
    let sys = system_valence("service_users_other_owner").await;
    seed_user(&sys, "maker-alice").await;
    seed_user(&sys, "maker-bob").await;
    let alice = user_valence(&sys, "maker-alice");

    for data in [
        row("maker-bob", "maker-alice", "for-bob"),
        row("maker-alice", "maker-bob", "framed"),
    ] {
        let id = ServiceUserId::new_v4();
        let err = direct_upsert(&alice, &id, data)
            .await
            .expect_err("not own service user");
        assert!(matches!(err, valence::Error::Privacy(_)), "{err:?}");
        assert!(stored_service_user(&sys, &id).await.is_none());
    }
}

#[tokio::test]
async fn service_user_create_missing_owner_sad() {
    setup();
    let sys = system_valence("service_users_no_owner").await;
    seed_user(&sys, "maker-alice").await;
    let alice = user_valence(&sys, "maker-alice");
    let now = Utc::now();
    let ownerless = ServiceUserAccount::new(
        None,
        ServiceUserAccountOwnerKind::User,
        Some(RecordId::new("user", "maker-alice")),
        "orphan".into(),
        "orphanbot".into(),
        "Orphan".into(),
        None,
        ServiceUserAccountStatus::Active,
        None,
        now,
        now,
    )
    .expect("row");
    let id = ServiceUserId::new_v4();

    let err = direct_upsert(&alice, &id, ownerless)
        .await
        .expect_err("owner required");
    assert!(matches!(err, valence::Error::Privacy(_)), "{err:?}");
    assert!(stored_service_user(&sys, &id).await.is_none());
}

// --- TM-B6: identity is immutable -------------------------------------------

async fn reassign(
    v: &Valence,
    id: &ServiceUserId,
    to: &str,
) -> valence::Result<ServiceUserAccount> {
    let service_user = ServiceUserAccount::get(id.as_str(), v, valence::use_!(r"**Test:** Load a **service user** for `service_users_privacy` owner-change attempts. CI and developers running the suite only."))
        .await?
        .ok_or_else(|| valence::Error::NotFound("service_user_account".into()))?;
    service_user.get_mutable(v, valence::use_!(r"**Test:** Attempt to change a **service user** owner for `service_users_privacy` so the suite can prove it is refused. CI and developers running the suite only."))
        .set_user(RecordId::new("user", to))?
        .commit()
        .await
}

#[tokio::test]
async fn service_user_owner_takeover_via_commit_sad() {
    setup();
    let sys = system_valence("service_users_takeover_commit").await;
    let (_, id, _) = seed_service_user(&sys, "maker-alice", "victim").await;
    seed_user(&sys, "maker-mallory").await;
    let mallory = user_valence(&sys, "maker-mallory");

    // Mallory loads the row through System's eyes (a forged in-memory copy) and
    // tries to commit herself as owner.
    let copy = ServiceUserAccount::get(id.as_str(), &sys, valence::use_!(r"**Test:** Fixture load of a **service user** to forge an attacker's in-memory copy for `service_users_privacy`. CI and developers running the suite only."))
        .await
        .expect("get")
        .expect("row");
    let err = copy
        .get_mutable(&mallory, valence::use_!(r"**Test:** Attacker owner change on a **service user** for `service_users_privacy`. CI and developers running the suite only."))
        .set_user(RecordId::new("user", "maker-mallory"))
        .expect("set")
        .commit()
        .await
        .expect_err("takeover refused");
    assert!(matches!(err, valence::Error::Privacy(_)), "{err:?}");
    let raw = stored_service_user(&sys, &id).await.expect("row");
    assert!(raw["user"].to_string().contains("maker-alice"), "{raw}");
}

#[tokio::test]
async fn service_user_owner_takeover_via_model_update_sad() {
    setup();
    let sys = system_valence("service_users_takeover_update").await;
    let (_, id, _) = seed_service_user(&sys, "maker-alice", "victim2").await;
    seed_user(&sys, "maker-mallory").await;
    let mallory = user_valence(&sys, "maker-mallory");

    // Plain `Model::update` skips the stored-row check when the caller cannot
    // read the row; SERVICE_USER_IDENTITY_IMMUTABLE re-reads it and blocks.
    let forged = row("maker-mallory", "maker-mallory", "victim2");
    let err = ServiceUserAccount::update(id.as_str(), forged, &mallory, valence::use_!(r"**Test:** Attacker replace of a **service user** via plain update for `service_users_privacy`. CI and developers running the suite only."))
        .await
        .expect_err("takeover refused");
    assert!(matches!(err, valence::Error::Privacy(_)), "{err:?}");
    let raw = stored_service_user(&sys, &id).await.expect("row");
    assert!(raw["user"].to_string().contains("maker-alice"), "{raw}");
    assert_eq!(raw["display_name"], "Test service user");
}

#[tokio::test]
async fn service_user_give_away_sad() {
    setup();
    let sys = system_valence("service_users_give_away").await;
    let (alice, id, _) = seed_service_user(&sys, "maker-alice", "gift").await;
    seed_user(&sys, "maker-bob").await;

    let err = reassign(&alice, &id, "maker-bob")
        .await
        .expect_err("give away refused");
    assert!(matches!(err, valence::Error::Privacy(_)), "{err:?}");
    assert!(stored_service_user(&sys, &id).await.expect("row")["user"]
        .to_string()
        .contains("maker-alice"));
}

#[tokio::test]
async fn super_user_cannot_reassign_owner_sad() {
    setup();
    let sys = system_valence("service_users_super_reassign").await;
    let (_, id, _) = seed_service_user(&sys, "maker-alice", "keep-owner").await;
    seed_user(&sys, "super-sam").await;
    let sam = user_valence(&sys, "super-sam");

    let err = reassign(&sam, &id, "super-sam")
        .await
        .expect_err("reassign refused");
    assert!(matches!(err, valence::Error::Privacy(_)), "{err:?}");
    // Even System cannot rename or reassign: the rule is always_block.
    let err = reassign(&sys, &id, "super-sam")
        .await
        .expect_err("System refused too");
    assert!(matches!(err, valence::Error::Privacy(_)), "{err:?}");
    assert!(stored_service_user(&sys, &id).await.expect("row")["user"]
        .to_string()
        .contains("maker-alice"));
}

#[tokio::test]
async fn service_user_handle_change_sad() {
    setup();
    let sys = system_valence("service_users_handle_change").await;
    let (alice, id, _) = seed_service_user(&sys, "maker-alice", "stable").await;

    let service_user = get_service_user(&alice, &id).await.expect("get");
    let err = service_user
        .get_mutable(&alice, valence::use_!(r"**Test:** Attempt to rename a **service user** for `service_users_privacy`. CI and developers running the suite only."))
        .set_handle("renamed".into())
        .expect("set")
        .commit()
        .await
        .expect_err("rename refused");
    assert!(matches!(err, valence::Error::Privacy(_)), "{err:?}");
    assert_eq!(
        stored_service_user(&sys, &id).await.expect("row")["handle"],
        "stable"
    );
}

// --- TM-B8: isolation -------------------------------------------------------

#[tokio::test]
async fn peer_read_service_user_not_found_sad() {
    setup();
    let sys = system_valence("service_users_peer_read").await;
    let (_, id, _) = seed_service_user(&sys, "maker-alice", "private").await;
    seed_user(&sys, "maker-bob").await;
    let bob = user_valence(&sys, "maker-bob");

    assert!(matches!(
        get_service_user(&bob, &id).await,
        Err(ServiceUserError::NotFound)
    ));
    let direct = ServiceUserAccount::get(id.as_str(), &bob, valence::use_!(r"**Test:** Peer read of a **service user** for `service_users_privacy`. CI and developers running the suite only."))
        .await
        .expect("get");
    assert!(direct.is_none());
}

#[tokio::test]
async fn peer_list_excludes_others_sad() {
    setup();
    let sys = system_valence("service_users_peer_list").await;
    seed_service_user(&sys, "maker-alice", "alices").await;
    let (bob, _, _) = seed_service_user(&sys, "maker-bob", "bobs").await;

    let listed = list_my_service_users(&bob).await.expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].handle(), "bobs");
    let all = ServiceUserAccount::query(&bob, valence::use_!(r"**Test:** Peer query over every **service user** for `service_users_privacy`. CI and developers running the suite only."))
        .await
        .expect("query");
    assert!(all.iter().all(|b| b.handle() != "alices"));
}

#[tokio::test]
async fn peer_suspend_delete_not_found_sad() {
    setup();
    let sys = system_valence("service_users_peer_write").await;
    let (_, id, _) = seed_service_user(&sys, "maker-alice", "untouchable").await;
    seed_user(&sys, "maker-bob").await;
    let bob = user_valence(&sys, "maker-bob");

    assert!(matches!(
        suspend_service_user(&bob, &id).await,
        Err(ServiceUserError::NotFound)
    ));
    assert!(matches!(
        update_service_user(
            &bob,
            &id,
            ServiceUserProfileUpdate {
                display_name: Some("Mine"),
                description: None
            }
        )
        .await,
        Err(ServiceUserError::NotFound)
    ));
    assert!(matches!(
        delete_service_user(&bob, &id).await,
        Err(ServiceUserError::NotFound)
    ));
    let raw = stored_service_user(&sys, &id).await.expect("row");
    assert_eq!(raw["status"], "active");
    assert_eq!(raw["display_name"], "Test service user");
    assert_eq!(stored_service_user_count(&sys, "maker-alice").await, 1);
}

#[tokio::test]
async fn service_user_actor_cannot_read_or_manage_itself_sad() {
    setup();
    let sys = system_valence("service_users_self").await;
    let (_, id, _) = seed_service_user(&sys, "maker-alice", "self").await;
    let as_service_user = sys.with_actor(id.actor());

    assert!(matches!(
        get_service_user(&as_service_user, &id).await,
        Err(ServiceUserError::NotAUser)
    ));
    assert!(matches!(
        suspend_service_user(&as_service_user, &id).await,
        Err(ServiceUserError::NotAUser)
    ));
    assert!(matches!(
        delete_service_user(&as_service_user, &id).await,
        Err(ServiceUserError::NotAUser)
    ));
    assert!(matches!(
        create_service_user(
            &as_service_user,
            NewServiceUser {
                handle: "child",
                display_name: "Child",
                description: None
            }
        )
        .await,
        Err(ServiceUserError::NotAUser)
    ));

    let direct = ServiceUserAccount::get(id.as_str(), &as_service_user, valence::use_!(r"**Test:** A service user reading its own **service user** row for `service_users_privacy`. CI and developers running the suite only."))
        .await
        .expect("get");
    assert!(direct.is_none(), "a service user cannot read itself in B1");
    let err = ServiceUserAccount::delete(id.as_str(), &as_service_user, valence::use_!(r"**Test:** A service user deleting its own **service user** row for `service_users_privacy`. CI and developers running the suite only."))
        .await
        .expect_err("service user cannot delete itself");
    assert!(matches!(err, valence::Error::Privacy(_)), "{err:?}");
    assert_eq!(
        stored_service_user(&sys, &id).await.expect("row")["status"],
        "active"
    );
}

#[tokio::test]
async fn infra_service_user_denied_sad() {
    setup();
    let sys = system_valence("service_users_infra").await;
    let (_, id, _) = seed_service_user(&sys, "maker-alice", "infra-target").await;
    let cron = sys.with_actor(Actor::ServiceUser {
        service_name: "cron".into(),
    });

    assert!(matches!(
        get_service_user(&cron, &id).await,
        Err(ServiceUserError::NotAUser)
    ));
    let direct = ServiceUserAccount::get(id.as_str(), &cron, valence::use_!(r"**Test:** A built-in service user reading a **service user** for `service_users_privacy`. CI and developers running the suite only."))
        .await
        .expect("get");
    assert!(direct.is_none());
    let new_id = ServiceUserId::new_v4();
    let err = direct_upsert(&cron, &new_id, row("maker-alice", "maker-alice", "cron"))
        .await
        .expect_err("service user cannot create");
    assert!(matches!(err, valence::Error::Privacy(_)), "{err:?}");
}

#[tokio::test]
async fn anonymous_denied_sad() {
    setup();
    let sys = system_valence("service_users_anon").await;
    let (_, id, _) = seed_service_user(&sys, "maker-alice", "anon-target").await;
    let anon = sys.with_actor(Actor::Anonymous);

    assert!(matches!(
        get_service_user(&anon, &id).await,
        Err(ServiceUserError::NotAUser)
    ));
    assert!(matches!(
        list_my_service_users(&anon).await,
        Err(ServiceUserError::NotAUser)
    ));
    let direct = ServiceUserAccount::get(id.as_str(), &anon, valence::use_!(r"**Test:** Anonymous read of a **service user** for `service_users_privacy`. CI and developers running the suite only."))
        .await
        .expect("get");
    assert!(direct.is_none());
}

#[tokio::test]
async fn super_user_lists_every_service_user_happy() {
    setup();
    let sys = system_valence("service_users_list_all").await;
    let (_, alice_id, _) = seed_service_user(&sys, "maker-list-alice", "alice-agent").await;
    let (_, bob_id, _) = seed_service_user(&sys, "maker-list-bob", "bob-agent").await;
    let (root, root_id, _) = seed_service_user(&sys, "super-list-root", "root-agent").await;

    let listed: Vec<ServiceUserId> = list_all_service_users(&root)
        .await
        .expect("manage-any lists all")
        .iter()
        .map(|s| ServiceUserId::parse(s.id().expect("id").id()).expect("service user id"))
        .collect();

    assert_eq!(listed.len(), 3, "{listed:?}");
    for id in [&alice_id, &bob_id, &root_id] {
        assert!(listed.contains(id), "{id}");
    }
}

#[tokio::test]
async fn list_all_hides_deleted_happy() {
    setup();
    let sys = system_valence("service_users_list_all_deleted").await;
    let (alice, alice_id, _) = seed_service_user(&sys, "maker-gone", "gone-agent").await;
    let (root, root_id, _) = seed_service_user(&sys, "super-gone-root", "kept-agent").await;
    delete_service_user(&alice, &alice_id)
        .await
        .expect("delete");

    let listed = list_all_service_users(&root).await.expect("list");

    assert_eq!(listed.len(), 1);
    assert_eq!(
        ServiceUserId::parse(listed[0].id().expect("id").id()).expect("id"),
        root_id
    );
}

#[tokio::test]
async fn list_all_without_manage_any_sad() {
    setup();
    let sys = system_valence("service_users_list_all_denied").await;
    let (alice, _, _) = seed_service_user(&sys, "maker-nosy", "nosy-agent").await;
    seed_service_user(&sys, "maker-other-list", "other-agent").await;

    let err = list_all_service_users(&alice)
        .await
        .expect_err("not manage-any");

    assert!(matches!(err, ServiceUserError::Forbidden), "{err:?}");
    let service_user = ServiceUserId::new_v4().actor();
    let err = list_all_service_users(&sys.with_actor(service_user))
        .await
        .expect_err("service user");
    assert!(matches!(err, ServiceUserError::NotAUser), "{err:?}");
}
