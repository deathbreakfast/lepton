//! `active_service_user_owner` and `SERVICE_USER_ACTIVE` against stored service users.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

#[path = "support/service_users.rs"]
mod service_users_support;

use lepton_auth::service_users::{delete_service_user, resume_service_user, suspend_service_user};
use lepton_identity::service_users::{active_service_user_owner, SERVICE_USER_ACTIVE};
use serde_json::json;
use service_users_support::{install_test_gate, seed_service_user, stored_service_user};
use support::system_valence;
use valence::{Actor, JsonActorContext, PolicyEvaluator, PrivacyOperation, Valence};

fn setup() {
    install_test_gate();
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
}

fn owner(user_id: &str) -> Actor {
    Actor::User {
        user_id: user_id.into(),
    }
}

async fn rule_admits(v: &Valence, actor: &Actor, record: &serde_json::Value) -> bool {
    let ctx = JsonActorContext::new(serde_json::to_value(actor).expect("actor json"));
    SERVICE_USER_ACTIVE
        .evaluate(PrivacyOperation::Read, record, &ctx, v)
        .await
        .expect("evaluate")
}

#[tokio::test]
async fn active_service_user_owner_happy() {
    setup();
    let sys = system_valence("service_users_resolver_active").await;
    let (_, id, _) = seed_service_user(&sys, "maker-alice", "resolver").await;

    let service_name = format!("svc:{}", id.as_str());
    assert_eq!(
        active_service_user_owner(&service_name, &sys).await,
        Some(owner("maker-alice"))
    );
    assert_eq!(
        active_service_user_owner(id.as_str(), &sys).await,
        Some(owner("maker-alice"))
    );
    // The answer does not depend on who asks, including the service user itself.
    let as_service_user = sys.with_actor(id.actor());
    assert_eq!(
        active_service_user_owner(&service_name, &as_service_user).await,
        Some(owner("maker-alice"))
    );
}

#[tokio::test]
async fn active_service_user_owner_suspended_sad() {
    setup();
    let sys = system_valence("service_users_resolver_suspended").await;
    let (alice, id, _) = seed_service_user(&sys, "maker-alice", "paused").await;

    suspend_service_user(&alice, &id).await.expect("suspend");
    assert_eq!(active_service_user_owner(id.as_str(), &sys).await, None);

    resume_service_user(&alice, &id).await.expect("resume");
    assert_eq!(
        active_service_user_owner(id.as_str(), &sys).await,
        Some(owner("maker-alice"))
    );
}

#[tokio::test]
async fn active_service_user_owner_pending_deletion_sad() {
    setup();
    let sys = system_valence("service_users_resolver_deleted").await;
    let (alice, id, _) = seed_service_user(&sys, "maker-alice", "doomed").await;

    delete_service_user(&alice, &id).await.expect("delete");
    let stored = stored_service_user(&sys, &id)
        .await
        .expect("row awaits purge");
    assert_eq!(stored["status"], "active");
    assert_eq!(active_service_user_owner(id.as_str(), &sys).await, None);
}

#[tokio::test]
async fn active_service_user_owner_non_canonical_sad() {
    setup();
    let sys = system_valence("service_users_resolver_non_canonical").await;
    let (_, id, _) = seed_service_user(&sys, "maker-alice", "canon").await;
    let bare = id.as_str();

    for raw in [
        format!("bot:{bare}"),
        format!("svc:svc:{bare}"),
        format!("svc:{}", bare.to_uppercase()),
        bare.replace('-', ""),
        format!("{bare} "),
        format!("service_user_account:{bare}"),
        "cron".to_string(),
        String::new(),
    ] {
        assert_eq!(active_service_user_owner(&raw, &sys).await, None, "{raw}");
    }
    assert_eq!(
        active_service_user_owner(
            &format!(
                "svc:{}",
                lepton_identity::service_users::ServiceUserId::new_v4()
            ),
            &sys
        )
        .await,
        None,
        "unknown id"
    );
}

#[tokio::test]
async fn service_user_active_rule_owner_reach_happy() {
    setup();
    let sys = system_valence("service_users_rule_reach").await;
    let (_, id, _) = seed_service_user(&sys, "maker-alice", "reacher").await;

    assert!(rule_admits(&sys, &id.actor(), &json!({"user": "user:maker-alice"})).await);
    assert!(
        rule_admits(
            &sys,
            &id.actor(),
            &json!({"user": {"tb": "user", "id": "maker-alice"}})
        )
        .await
    );
}

#[tokio::test]
async fn service_user_active_rule_nothing_else_sad() {
    setup();
    let sys = system_valence("service_users_rule_nothing_else").await;
    let (alice, id, _) = seed_service_user(&sys, "maker-alice", "limited").await;
    let alices_row = json!({"user": "user:maker-alice"});

    // Someone else's row, or a row with no owner.
    assert!(!rule_admits(&sys, &id.actor(), &json!({"user": "user:maker-bob"})).await);
    assert!(!rule_admits(&sys, &id.actor(), &json!({"title": "no owner"})).await);

    // Other actors gain nothing from this rule, the owner included.
    for actor in [
        Actor::User {
            user_id: "maker-alice".into(),
        },
        Actor::ServiceUser {
            service_name: "cron".into(),
        },
        Actor::ServiceUser {
            service_name: format!("bot:{}", id.as_str()),
        },
        Actor::Anonymous,
        Actor::System {
            operation: "resolver".into(),
        },
    ] {
        assert!(!rule_admits(&sys, &actor, &alices_row).await, "{actor:?}");
    }

    // A suspended service user loses the owner's reach.
    suspend_service_user(&alice, &id).await.expect("suspend");
    assert!(!rule_admits(&sys, &id.actor(), &alices_row).await);
}
