//! Access tokens for service users: create, verify, revoke, and every refusal.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

#[path = "support/service_users.rs"]
mod service_users_support;

use chrono::{Duration, Utc};
use lepton_auth::service_users::{
    create_service_user_token, delete_service_user, list_service_user_tokens, resume_service_user,
    revoke_service_user_token, suspend_service_user, NewServiceUserToken, ServiceUserError,
    MAX_TOKENS_PER_SERVICE_USER,
};
use lepton_host_adapter::generated::ServiceUserToken as TokenRow;
use lepton_identity::service_users::{verify_bearer_token, ServiceUserToken};
use service_users_support::{install_test_gate, seed_service_user, seed_user, SUPER};
use support::{system_valence, user_valence};
use valence::{Actor, Model, RecordId};

fn setup() {
    install_test_gate();
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
}

/// Raw stored row, bypassing privacy.
async fn stored_token(sys: &valence::Valence, id: &str) -> Option<serde_json::Value> {
    let backend = sys
        .backend_for_table("service_user_token")
        .expect("backend");
    valence::get_record(backend.as_ref(), "service_user_token", id, valence::use_!(r"**Test:** Fixture read of a **service user token** row so the suite can assert what was stored, independent of privacy. CI and developers running the suite only."))
        .await
        .expect("raw read")
}

fn in_days(days: i64) -> chrono::DateTime<Utc> {
    Utc::now() + Duration::days(days)
}

fn new_token(label: &str) -> NewServiceUserToken<'_> {
    NewServiceUserToken {
        label,
        expires_at: in_days(30),
    }
}

#[tokio::test]
async fn create_and_verify_happy() {
    setup();
    let sys = system_valence("tokens_happy").await;
    let (alice, id, _) = seed_service_user(&sys, "maker-tok-a", "tok-happy").await;

    let created = create_service_user_token(&alice, &id, new_token("ci"))
        .await
        .expect("create");
    assert!(created.token.starts_with("lpt_"));

    let verified = verify_bearer_token(&created.token, &sys)
        .await
        .expect("verify");
    assert_eq!(verified.service_user, id);
    assert_eq!(verified.actor(), id.actor());
    assert_eq!(
        verified.owner,
        Actor::User {
            user_id: "maker-tok-a".into()
        }
    );

    // The row never holds the plaintext secret.
    let secret = created.token.rsplit('_').next().expect("secret");
    let token_id = created.row.id().expect("id").id().to_string();
    let stored = stored_token(&sys, &token_id)
        .await
        .expect("row")
        .to_string();
    assert!(!stored.contains(secret));
    assert!(!format!("{created:?}").contains(secret));
}

#[tokio::test]
async fn wrong_or_malformed_token_sad() {
    setup();
    let sys = system_valence("tokens_wrong").await;
    let (alice, id, _) = seed_service_user(&sys, "maker-tok-b", "tok-wrong").await;
    let created = create_service_user_token(&alice, &id, new_token("ci"))
        .await
        .expect("create");

    let (head, _) = created.token.rsplit_once('_').expect("shape");
    let forged = format!("{head}_{}", "0".repeat(64));
    for bad in [forged.as_str(), "lpt_nope", "", "Bearer x", "svc:abc"] {
        assert!(verify_bearer_token(bad, &sys).await.is_none(), "{bad}");
    }
}

#[tokio::test]
async fn revoked_token_refused_sad() {
    setup();
    let sys = system_valence("tokens_revoked").await;
    let (alice, id, _) = seed_service_user(&sys, "maker-tok-c", "tok-revoke").await;
    let created = create_service_user_token(&alice, &id, new_token("ci"))
        .await
        .expect("create");
    let token_id = created.row.id().expect("id").id().to_string();

    revoke_service_user_token(&alice, &id, &token_id)
        .await
        .expect("revoke");
    assert!(verify_bearer_token(&created.token, &sys).await.is_none());
    // Revoking twice is fine.
    revoke_service_user_token(&alice, &id, &token_id)
        .await
        .expect("revoke again");
}

#[tokio::test]
async fn expiry_bounds_sad() {
    setup();
    let sys = system_valence("tokens_expiry").await;
    let (alice, id, _) = seed_service_user(&sys, "maker-tok-d", "tok-expiry").await;
    for expires_at in [Utc::now() - Duration::seconds(5), in_days(366)] {
        let err = create_service_user_token(
            &alice,
            &id,
            NewServiceUserToken {
                label: "x",
                expires_at,
            },
        )
        .await
        .expect_err("bad expiry");
        assert!(matches!(
            err,
            ServiceUserError::InvalidProfile {
                field: "expires_at"
            }
        ));
    }
    for label in ["", "   ", &"x".repeat(81)] {
        let err = create_service_user_token(&alice, &id, new_token(label))
            .await
            .expect_err("bad label");
        assert!(matches!(
            err,
            ServiceUserError::InvalidProfile { field: "label" }
        ));
    }
}

#[tokio::test]
async fn suspended_service_user_refused_then_resumed() {
    setup();
    let sys = system_valence("tokens_suspended").await;
    let (alice, id, _) = seed_service_user(&sys, "maker-tok-e", "tok-suspend").await;
    let created = create_service_user_token(&alice, &id, new_token("ci"))
        .await
        .expect("create");

    suspend_service_user(&alice, &id).await.expect("suspend");
    assert!(verify_bearer_token(&created.token, &sys).await.is_none());
    resume_service_user(&alice, &id).await.expect("resume");
    assert!(verify_bearer_token(&created.token, &sys).await.is_some());
}

#[tokio::test]
async fn deleted_service_user_refused_sad() {
    setup();
    let sys = system_valence("tokens_deleted").await;
    let (alice, id, _) = seed_service_user(&sys, "maker-tok-f", "tok-delete").await;
    let created = create_service_user_token(&alice, &id, new_token("ci"))
        .await
        .expect("create");
    delete_service_user(&alice, &id).await.expect("delete");
    assert!(verify_bearer_token(&created.token, &sys).await.is_none());
}

#[tokio::test]
async fn token_limit_sad() {
    setup();
    let sys = system_valence("tokens_limit").await;
    let (alice, id, _) = seed_service_user(&sys, "maker-tok-g", "tok-limit").await;
    let mut first = None;
    for i in 0..MAX_TOKENS_PER_SERVICE_USER {
        let t = create_service_user_token(&alice, &id, new_token(&format!("t{i}")))
            .await
            .expect("under limit");
        first.get_or_insert(t);
    }
    let err = create_service_user_token(&alice, &id, new_token("over"))
        .await
        .expect_err("over limit");
    assert!(matches!(err, ServiceUserError::QuotaReached { .. }));

    // Revoking frees a slot.
    let first = first.expect("first");
    revoke_service_user_token(&alice, &id, first.row.id().expect("id").id())
        .await
        .expect("revoke");
    create_service_user_token(&alice, &id, new_token("again"))
        .await
        .expect("slot freed");
}

#[tokio::test]
async fn only_the_owner_manages_tokens_sad() {
    setup();
    let sys = system_valence("tokens_privacy").await;
    let (alice, id, _) = seed_service_user(&sys, "maker-tok-h", "tok-priv").await;
    let created = create_service_user_token(&alice, &id, new_token("ci"))
        .await
        .expect("create");
    let token_id = created.row.id().expect("id").id().to_string();

    seed_user(&sys, "maker-tok-mallory").await;
    let mallory = user_valence(&sys, "maker-tok-mallory");
    assert!(matches!(
        create_service_user_token(&mallory, &id, new_token("x")).await,
        Err(ServiceUserError::NotFound)
    ));
    assert!(matches!(
        list_service_user_tokens(&mallory, &id).await,
        Err(ServiceUserError::NotFound)
    ));
    assert!(matches!(
        revoke_service_user_token(&mallory, &id, &token_id).await,
        Err(ServiceUserError::NotFound)
    ));

    // A manage-any user can list and revoke, but not create.
    seed_user(&sys, &format!("{SUPER}-tok")).await;
    let admin = user_valence(&sys, format!("{SUPER}-tok"));
    assert_eq!(
        list_service_user_tokens(&admin, &id)
            .await
            .expect("list")
            .len(),
        1
    );
    assert!(create_service_user_token(&admin, &id, new_token("x"))
        .await
        .is_err());
    revoke_service_user_token(&admin, &id, &token_id)
        .await
        .expect("admin revokes");
    assert!(verify_bearer_token(&created.token, &sys).await.is_none());
}

#[tokio::test]
async fn a_service_user_cannot_manage_tokens_sad() {
    setup();
    let sys = system_valence("tokens_self").await;
    let (alice, id, _) = seed_service_user(&sys, "maker-tok-i", "tok-self").await;
    let created = create_service_user_token(&alice, &id, new_token("ci"))
        .await
        .expect("create");
    let as_service_user = sys.with_actor(id.actor());
    assert!(matches!(
        create_service_user_token(&as_service_user, &id, new_token("x")).await,
        Err(ServiceUserError::NotAUser)
    ));
    assert!(matches!(
        revoke_service_user_token(&as_service_user, &id, created.row.id().expect("id").id()).await,
        Err(ServiceUserError::NotAUser)
    ));
}

#[tokio::test]
async fn owner_deletion_removes_tokens() {
    setup();
    let sys = system_valence("tokens_owner_delete").await;
    let (alice, id, _) = seed_service_user(&sys, "maker-tok-j", "tok-owner").await;
    let created = create_service_user_token(&alice, &id, new_token("ci"))
        .await
        .expect("create");
    lepton_auth::identity_delete::delete_user(&sys, &valence::RecordId::new("user", "maker-tok-j"))
        .await
        .expect("erase owner");
    assert!(verify_bearer_token(&created.token, &sys).await.is_none());
    let token_id = created.row.id().expect("id").id().to_string();
    assert!(
        stored_token(&sys, &token_id).await.is_none(),
        "token row removed with its owner"
    );
}

#[tokio::test]
async fn expired_token_refused_sad() {
    setup();
    let sys = system_valence("tokens_expired").await;
    let (alice, id, _) = seed_service_user(&sys, "maker-tok-k", "tok-expired").await;
    let token = ServiceUserToken::generate();
    let row = TokenRow::new(
        Some(RecordId::new("user", "maker-tok-k")),
        Some(RecordId::new("service_user_account", id.as_str())),
        "old".into(),
        token.hash(),
        Utc::now() - Duration::seconds(10),
        None,
        Utc::now() - Duration::days(1),
    )
    .expect("row");
    TokenRow::upsert(token.id(), row, &alice, valence::use_!(r"**Test:** Fixture save of an already expired **service user token** so the suite can check expiry is enforced. CI and developers running the suite only."))
        .await
        .expect("seed expired token");
    assert!(verify_bearer_token(&token.expose(), &sys).await.is_none());
}

#[tokio::test]
async fn owner_cannot_repoint_or_rehash_a_token_sad() {
    setup();
    let sys = system_valence("tokens_immutable").await;
    let (alice, id, _) = seed_service_user(&sys, "maker-tok-l", "tok-immut").await;
    let (_, other, _) = seed_service_user(&sys, "maker-tok-m", "tok-other").await;
    let created = create_service_user_token(&alice, &id, new_token("ci"))
        .await
        .expect("create");

    let repoint = created
        .row
        .get_mutable(&alice, valence::use_!(r"**Test:** Attempt to repoint a **service user token** at another service user, which must be refused. CI and developers running the suite only."))
        .set_service_user(RecordId::new("service_user_account", other.as_str()))
        .expect("set")
        .commit()
        .await;
    assert!(repoint.is_err(), "service_user is immutable");

    let rehash = created
        .row
        .get_mutable(&alice, valence::use_!(r"**Test:** Attempt to replace the secret hash of a **service user token**, which must be refused. CI and developers running the suite only."))
        .set_token_hash("0".repeat(64))
        .expect("set")
        .commit()
        .await;
    assert!(rehash.is_err(), "token_hash is immutable");
    assert!(verify_bearer_token(&created.token, &sys).await.is_some());
}

#[tokio::test]
async fn forged_row_for_foreign_service_user_refused_sad() {
    setup();
    let sys = system_valence("tokens_forged").await;
    let (_, victim, _) = seed_service_user(&sys, "maker-tok-n", "tok-victim").await;
    seed_user(&sys, "maker-tok-evil").await;
    let evil = user_valence(&sys, "maker-tok-evil");
    let row = TokenRow::new(
        Some(RecordId::new("user", "maker-tok-evil")),
        Some(RecordId::new("service_user_account", victim.as_str())),
        "forged".into(),
        ServiceUserToken::generate().hash(),
        in_days(1),
        None,
        Utc::now(),
    )
    .expect("row");
    let saved = TokenRow::upsert("forged-id", row, &evil, valence::use_!(r"**Test:** Attempt to save a **service user token** for a service user the caller does not own, which must be refused. CI and developers running the suite only."))
        .await;
    assert!(saved.is_err(), "create rule checks service user ownership");
}
