//! Access tokens for service users: create with scopes, verify, revoke, and every refusal.
//!
//! Tokens are minted through `create_service_user_token_without_step_up` (`test-utils`): the
//! step-up check needs an HTTP session these suites don't have.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

#[path = "support/service_users.rs"]
mod service_users_support;

use chrono::{Duration, Utc};
use lepton_auth::service_users::{
    create_service_user_token_without_step_up as create_service_user_token, delete_service_user,
    list_service_user_tokens, resume_service_user, revoke_service_user_token, suspend_service_user,
    NewServiceUserToken, ServiceUserError, MAX_TOKENS_PER_SERVICE_USER,
};
use lepton_host_adapter::generated::{ServiceUserToken as TokenRow, ServiceUserTokenKind};
use lepton_identity::service_users::ServiceUserId;
use lepton_identity::tokens::{
    record_token_use, scopes_to_json, verify_bearer_token, LeptonToken, TokenLifetime,
    TokenPrincipal, VerifiedToken,
};
use service_users_support::{
    install_test_gate, install_test_scopes, scope, seed_service_user, seed_user, MAGNON_READ,
    SUPER, TEST_SCOPES,
};
use support::{system_valence, user_valence};
use valence::{Actor, Model, RecordId};

fn setup() {
    install_test_gate();
    install_test_scopes();
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
}

/// The service user a verified token acts as, or a panic for a personal token.
fn service_user_of(verified: &VerifiedToken) -> (&ServiceUserId, &Actor) {
    match &verified.principal {
        TokenPrincipal::ServiceUser {
            service_user,
            owner,
            ..
        } => (service_user, owner),
        TokenPrincipal::Person(_) => panic!("expected a service user token"),
    }
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
        scopes: &MAGNON_READ,
        lifetime: TokenLifetime::Days30,
        kind: ServiceUserTokenKind::Manual,
        device_id: None,
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
    assert!(created.token.starts_with("lptk_"));
    let days = (*created.row.expires_at() - Utc::now()).num_days();
    assert!((29..=30).contains(&days), "30-day lifetime, got {days}");

    let verified = verify_bearer_token(&created.token, &sys)
        .await
        .expect("verify");
    let (service_user, owner) = service_user_of(&verified);
    assert_eq!(service_user, &id);
    assert_eq!(verified.principal.actor(), id.actor());
    assert_eq!(
        owner,
        &Actor::User {
            user_id: "maker-tok-a".into()
        }
    );
    assert_eq!(verified.scopes, *MAGNON_READ);
    assert!(verified.has_scope(&scope("magnon:read")));
    assert!(!verified.has_scope(&scope("magnon:write")));
    assert!(matches!(
        verified.principal,
        TokenPrincipal::ServiceUser {
            kind: ServiceUserTokenKind::Manual,
            device_id: None,
            ..
        }
    ));

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
    let retired = created.token.replacen("lptk_", "lpt_", 1);
    for bad in [
        forged.as_str(),
        retired.as_str(),
        "lptk_nope",
        "",
        "Bearer x",
        "svc:abc",
    ] {
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
async fn bad_label_scopes_or_device_refused_sad() {
    setup();
    let sys = system_valence("tokens_validation").await;
    let (alice, id, _) = seed_service_user(&sys, "maker-tok-d", "tok-valid").await;
    for label in ["", "   ", &"x".repeat(81)] {
        let err = create_service_user_token(&alice, &id, new_token(label))
            .await
            .expect_err("bad label");
        assert!(matches!(
            err,
            ServiceUserError::InvalidProfile { field: "label" }
        ));
    }
    let unregistered = [scope("magnon:read"), scope("billing:write")];
    for scopes in [&[][..], &unregistered[..]] {
        let err = create_service_user_token(
            &alice,
            &id,
            NewServiceUserToken {
                scopes,
                ..new_token("ci")
            },
        )
        .await
        .expect_err("bad scopes");
        assert!(matches!(
            err,
            ServiceUserError::InvalidProfile { field: "scopes" }
        ));
    }
    let long_device = "d".repeat(129);
    for (kind, device_id) in [
        (ServiceUserTokenKind::Manual, Some("laptop-1")),
        (ServiceUserTokenKind::Device, Some("  ")),
        (ServiceUserTokenKind::Device, Some(long_device.as_str())),
    ] {
        let err = create_service_user_token(
            &alice,
            &id,
            NewServiceUserToken {
                kind,
                device_id,
                ..new_token("ci")
            },
        )
        .await
        .expect_err("bad device");
        assert!(matches!(
            err,
            ServiceUserError::InvalidProfile { field: "device_id" }
        ));
    }
    assert!(list_service_user_tokens(&alice, &id)
        .await
        .expect("list")
        .is_empty());
}

#[tokio::test]
async fn device_token_with_scopes_and_90_days_happy() {
    setup();
    let sys = system_valence("tokens_device").await;
    let (alice, id, _) = seed_service_user(&sys, "maker-tok-dv", "tok-device").await;
    let created = create_service_user_token(
        &alice,
        &id,
        NewServiceUserToken {
            label: "kitchen screen",
            scopes: &TEST_SCOPES,
            lifetime: TokenLifetime::Days90,
            kind: ServiceUserTokenKind::Device,
            device_id: Some("dev-123"),
        },
    )
    .await
    .expect("create");
    let days = (*created.row.expires_at() - Utc::now()).num_days();
    assert!((89..=90).contains(&days), "90-day lifetime, got {days}");
    assert_eq!(created.row.kind(), Some(&ServiceUserTokenKind::Device));
    assert_eq!(created.row.device_id().map(String::as_str), Some("dev-123"));

    let verified = verify_bearer_token(&created.token, &sys)
        .await
        .expect("verify");
    let mut expected = TEST_SCOPES.clone();
    expected.sort();
    assert_eq!(verified.scopes, expected);
    assert!(matches!(
        &verified.principal,
        TokenPrincipal::ServiceUser {
            kind: ServiceUserTokenKind::Device,
            device_id: Some(d),
            ..
        } if d == "dev-123"
    ));
    // A device without a device record yet is fine too.
    create_service_user_token(
        &alice,
        &id,
        NewServiceUserToken {
            kind: ServiceUserTokenKind::Device,
            ..new_token("phone")
        },
    )
    .await
    .expect("device token without a device id");
}

#[tokio::test]
async fn service_user_records_its_own_last_use_only() {
    setup();
    let sys = system_valence("tokens_touch").await;
    let (alice, id, _) = seed_service_user(&sys, "maker-tok-t", "tok-touch").await;
    let (_, other, _) = seed_service_user(&sys, "maker-tok-t2", "tok-touch-other").await;
    let created = create_service_user_token(&alice, &id, new_token("ci"))
        .await
        .expect("create");
    let verified = verify_bearer_token(&created.token, &sys)
        .await
        .expect("verify");
    assert!(verified.last_used_at.is_none());

    let as_service_user = sys.with_actor(id.actor());
    record_token_use(&verified, &sys, &as_service_user)
        .await
        .expect("service user records its own use");
    let again = verify_bearer_token(&created.token, &sys)
        .await
        .expect("verify");
    assert!(again.last_used_at.is_some());

    // Another service user cannot touch this token.
    let as_other = sys.with_actor(other.actor());
    assert!(record_token_use(&verified, &sys, &as_other).await.is_err());

    // The touch rule allows `last_used_at` only: a service user cannot revoke or relabel.
    let row: TokenRow =
        serde_json::from_value(stored_token(&sys, &verified.token_id).await.expect("row"))
            .expect("row parses");
    let revoke = row
        .get_mutable(&as_service_user, valence::use_!(r"**Test:** Attempt by a **service user** to revoke its own token through the last-use rule, which must be refused. CI and developers running the suite only."))
        .set_revoked_at(Utc::now())
        .expect("set")
        .commit()
        .await;
    assert!(revoke.is_err(), "touch rule allows last_used_at only");
    assert!(verify_bearer_token(&created.token, &sys).await.is_some());
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
    let token = LeptonToken::generate();
    let row = TokenRow::new(
        Some(RecordId::new("user", "maker-tok-k")),
        Some(RecordId::new("service_user_account", id.as_str())),
        "old".into(),
        token.hash(),
        Some(scopes_to_json(&MAGNON_READ)),
        None,
        None,
        Utc::now() - Duration::seconds(10),
        None,
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

    let widen = created
        .row
        .get_mutable(&alice, valence::use_!(r"**Test:** Attempt to widen the scopes of a **service user token**, which must be refused. CI and developers running the suite only."))
        .set_scopes(scopes_to_json(&TEST_SCOPES))
        .expect("set")
        .commit()
        .await;
    assert!(widen.is_err(), "scopes are immutable");
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
        LeptonToken::generate().hash(),
        Some(scopes_to_json(&MAGNON_READ)),
        None,
        None,
        in_days(1),
        None,
        None,
        Utc::now(),
    )
    .expect("row");
    let saved = TokenRow::upsert("forged-id", row, &evil, valence::use_!(r"**Test:** Attempt to save a **service user token** for a service user the caller does not own, which must be refused. CI and developers running the suite only."))
        .await;
    assert!(saved.is_err(), "create rule checks service user ownership");
}

#[tokio::test]
async fn token_create_and_revoke_land_in_history_happy() {
    use lepton_auth::service_users::list_service_user_activity;
    use lepton_host_adapter::generated::ServiceUserActivityKind as Kind;

    setup();
    let sys = system_valence("tokens_history").await;
    let (alice, id, _) = seed_service_user(&sys, "maker-tok-o", "tok-history").await;
    let created = create_service_user_token(&alice, &id, new_token("deploy"))
        .await
        .expect("create");
    let token_id = created.row.id().expect("id").id().to_string();
    revoke_service_user_token(&alice, &id, &token_id)
        .await
        .expect("revoke");
    // A second revoke changes nothing and adds no entry.
    revoke_service_user_token(&alice, &id, &token_id)
        .await
        .expect("revoke again");

    let rows = list_service_user_activity(&alice, &id, None)
        .await
        .expect("history");
    let kinds: Vec<_> = rows.iter().map(|r| r.kind().clone()).collect();
    assert_eq!(
        kinds,
        [Kind::TokenRevoked, Kind::TokenCreated, Kind::Created]
    );
    assert_eq!(rows[0].detail().map(String::as_str), Some("deploy"));
}
