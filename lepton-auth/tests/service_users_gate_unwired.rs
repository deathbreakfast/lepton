//! With no `ServiceUserGate` installed, nobody can create service users, at the service or the
//! model layer (TM-B4). Its own binary, because the gate is process-wide.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

#[path = "support/service_users.rs"]
mod service_users_support;

use chrono::Utc;
use lepton_auth::service_users::{
    create_service_user, suggest_service_user_handle, NewServiceUser, ServiceUserError,
};
use lepton_host_adapter::generated::{
    ServiceUserAccount, ServiceUserAccountOwnerKind, ServiceUserAccountStatus,
};
use lepton_identity::service_users::{installed_service_user_gate, ServiceUserId};
use service_users_support::{seed_user, stored_service_user, stored_service_user_count};
use valence::{Model, RecordId};

use support::{system_valence, user_valence};

#[tokio::test]
async fn create_without_gate_sad() {
    assert!(
        installed_service_user_gate().is_none(),
        "this binary never installs a gate"
    );
    let sys = system_valence("service_users_unwired").await;
    seed_user(&sys, "maker-alice").await;
    let alice = user_valence(&sys, "maker-alice");

    let err = create_service_user(
        &alice,
        NewServiceUser {
            handle: "lonely",
            display_name: "Lonely",
            description: None,
        },
    )
    .await
    .expect_err("no gate");
    assert!(matches!(err, ServiceUserError::GateNotInstalled), "{err:?}");
    assert!(matches!(
        suggest_service_user_handle(&alice, "lonely").await,
        Err(ServiceUserError::GateNotInstalled)
    ));
    assert_eq!(stored_service_user_count(&sys, "maker-alice").await, 0);

    // The model layer refuses too: the create rule fails closed.
    let now = Utc::now();
    let owner = RecordId::new("user", "maker-alice");
    let row = ServiceUserAccount::new(
        Some(owner.clone()),
        ServiceUserAccountOwnerKind::User,
        Some(owner),
        "lonely".into(),
        "lonelybot".into(),
        "Lonely".into(),
        None,
        ServiceUserAccountStatus::Active,
        None,
        now,
        now,
    )
    .expect("row");
    let id = ServiceUserId::new_v4();
    let err = ServiceUserAccount::upsert(id.as_str(), row, &alice, valence::use_!(r"**Test:** Direct **service user** save with no gate installed for `service_users_gate_unwired`. CI and developers running the suite only."))
        .await
        .expect_err("rule fails closed");
    assert!(matches!(err, valence::Error::Privacy(_)), "{err:?}");
    assert!(stored_service_user(&sys, &id).await.is_none());
}
