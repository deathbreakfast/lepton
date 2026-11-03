//! Service user history: lifecycle rows, token events, listing, privacy, and cleanup.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

#[path = "support/service_users.rs"]
mod service_users_support;

use lepton_auth::identity_delete::delete_user;
use lepton_auth::service_users::{
    list_service_user_activity, record_service_user_token_activity, resume_service_user,
    suspend_service_user, update_service_user, ServiceUserError, ServiceUserProfileUpdate,
    ServiceUserTokenEvent, MAX_ACTIVITY_LIMIT,
};
use lepton_host_adapter::generated::{ServiceUserActivity, ServiceUserActivityKind as Kind};
use service_users_support::{install_test_gate, seed_service_user, seed_user};
use support::{system_valence, user_valence};
use valence::{Actor, RecordId};

fn setup() {
    install_test_gate();
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
}

fn kinds(rows: &[ServiceUserActivity]) -> Vec<Kind> {
    rows.iter().map(|r| r.kind().clone()).collect()
}

#[tokio::test]
async fn lifecycle_writes_history_newest_first_happy() {
    setup();
    let sys = system_valence("su_activity_lifecycle").await;
    let (owner, id, _) = seed_service_user(&sys, "maker-act1", "act-one").await;
    update_service_user(
        &owner,
        &id,
        ServiceUserProfileUpdate {
            display_name: Some("Renamed"),
            ..Default::default()
        },
    )
    .await
    .expect("update");
    suspend_service_user(&owner, &id).await.expect("suspend");
    resume_service_user(&owner, &id).await.expect("resume");

    let rows = list_service_user_activity(&owner, &id, None)
        .await
        .expect("list");
    assert_eq!(
        kinds(&rows),
        [Kind::Resumed, Kind::Suspended, Kind::Updated, Kind::Created]
    );
    assert_eq!(rows[0].actor().map(RecordId::id), Some("maker-act1"));
    assert!(rows.iter().all(|r| r.detail().is_none()));
}

#[tokio::test]
async fn limit_is_respected_and_capped_happy() {
    setup();
    let sys = system_valence("su_activity_limit").await;
    let (owner, id, _) = seed_service_user(&sys, "maker-act2", "act-two").await;
    suspend_service_user(&owner, &id).await.expect("suspend");
    resume_service_user(&owner, &id).await.expect("resume");

    let two = list_service_user_activity(&owner, &id, Some(2))
        .await
        .expect("list");
    assert_eq!(kinds(&two), [Kind::Resumed, Kind::Suspended]);
    let all = list_service_user_activity(&owner, &id, Some(MAX_ACTIVITY_LIMIT * 10))
        .await
        .expect("list");
    assert_eq!(all.len(), 3);
}

#[tokio::test]
async fn token_events_appear_with_label_happy() {
    setup();
    let sys = system_valence("su_activity_token").await;
    let (owner, id, _) = seed_service_user(&sys, "maker-act3", "act-three").await;
    record_service_user_token_activity(
        &owner,
        &id,
        ServiceUserTokenEvent::Created,
        Some("claude-code"),
    )
    .await
    .expect("record");
    record_service_user_token_activity(&owner, &id, ServiceUserTokenEvent::Revoked, None)
        .await
        .expect("record");

    let rows = list_service_user_activity(&owner, &id, None)
        .await
        .expect("list");
    assert_eq!(
        kinds(&rows),
        [Kind::TokenRevoked, Kind::TokenCreated, Kind::Created]
    );
    assert_eq!(rows[1].detail().map(String::as_str), Some("claude-code"));
}

#[tokio::test]
async fn super_user_reads_and_records_for_other_owner_happy() {
    setup();
    let sys = system_valence("su_activity_super").await;
    let (_, id, _) = seed_service_user(&sys, "maker-act4", "act-four").await;
    seed_user(&sys, "super-act4").await;
    let admin = user_valence(&sys, "super-act4");

    record_service_user_token_activity(&admin, &id, ServiceUserTokenEvent::Rotated, None)
        .await
        .expect("super user records");
    let rows = list_service_user_activity(&admin, &id, None)
        .await
        .expect("super user lists");
    assert_eq!(rows[0].kind(), &Kind::TokenRotated);
    assert_eq!(rows[0].actor().map(RecordId::id), Some("super-act4"));
    assert_eq!(rows[0].user().map(RecordId::id), Some("maker-act4"));
}

#[tokio::test]
async fn stranger_and_service_user_actors_see_not_found_sad() {
    setup();
    let sys = system_valence("su_activity_stranger").await;
    let (_, id, _) = seed_service_user(&sys, "maker-act5", "act-five").await;
    seed_user(&sys, "maker-other5").await;
    let other = user_valence(&sys, "maker-other5");

    assert!(matches!(
        list_service_user_activity(&other, &id, None).await,
        Err(ServiceUserError::NotFound)
    ));
    assert!(matches!(
        record_service_user_token_activity(&other, &id, ServiceUserTokenEvent::Created, None).await,
        Err(ServiceUserError::NotFound)
    ));
    let as_service_user = sys.with_actor(id.actor());
    assert!(matches!(
        list_service_user_activity(&as_service_user, &id, None).await,
        Err(ServiceUserError::NotAUser)
    ));
    let anon = sys.with_actor(Actor::Anonymous);
    assert!(matches!(
        list_service_user_activity(&anon, &id, None).await,
        Err(ServiceUserError::NotAUser)
    ));
}

#[tokio::test]
async fn long_label_is_refused_sad() {
    setup();
    let sys = system_valence("su_activity_label").await;
    let (owner, id, _) = seed_service_user(&sys, "maker-act6", "act-six").await;
    let label = "x".repeat(121);
    assert!(matches!(
        record_service_user_token_activity(
            &owner,
            &id,
            ServiceUserTokenEvent::Created,
            Some(&label)
        )
        .await,
        Err(ServiceUserError::InvalidProfile { field: "label" })
    ));
}

#[tokio::test]
async fn rows_cannot_be_changed_by_anyone_sad() {
    setup();
    let sys = system_valence("su_activity_append_only").await;
    let (owner, id, _) = seed_service_user(&sys, "maker-act7", "act-seven").await;
    let rows = list_service_user_activity(&owner, &id, None)
        .await
        .expect("list");
    let row_id = rows[0].id().expect("id").id().to_string();

    for v in [&owner, &sys] {
        let edit = rows[0]
            .clone()
            .get_mutable(v, valence::use_!(r"**Test:** Attempted edit of a **service user history** row so the suite can prove history is append-only. CI and developers running the suite only."))
            .set_detail("tampered".to_string());
        let result = match edit {
            Ok(edit) => edit.commit().await.map(|_| ()),
            Err(e) => Err(e),
        };
        assert!(result.is_err(), "history row {row_id} must not change");
    }
    let again = list_service_user_activity(&owner, &id, None)
        .await
        .expect("list");
    assert!(again[0].detail().is_none());
}

#[tokio::test]
async fn owner_erasure_removes_history_happy() {
    setup();
    let sys = system_valence("su_activity_erasure").await;
    let (owner, id, _) = seed_service_user(&sys, "maker-act9", "act-nine").await;
    suspend_service_user(&owner, &id).await.expect("suspend");

    delete_user(&sys, &RecordId::new("user", "maker-act9"))
        .await
        .expect("erase owner");

    let left = ServiceUserActivity::get_from_service_user_id(
        id.as_str(),
        &sys,
        valence::use_!(r"**Test:** Fixture read of **service user history** after its owner is erased so the suite can prove the history goes with the account. CI and developers running the suite only."),
    )
    .await
    .expect("read");
    assert!(left.is_empty(), "history must go with the owner: {left:?}");
}
