//! Personal tokens: create with scopes, list, revoke, verify, and every refusal.
//!
//! Tokens are minted through `create_personal_token_without_step_up` (`test-utils`): the
//! step-up check needs an HTTP session these suites don't have.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

#[path = "support/service_users.rs"]
mod service_users_support;

use chrono::{Duration, Utc};
use lepton_auth::tokens::{
    create_personal_token_without_step_up as create_personal_token, list_personal_tokens,
    revoke_personal_token, NewPersonalToken, PersonalTokenError, MAX_PERSONAL_TOKENS,
};
use lepton_host_adapter::generated::{PersonalToken as TokenRow, User, UserStatus};
use lepton_identity::tokens::{
    record_token_use, scopes_to_json, verify_bearer_token, LeptonToken, TokenLifetime,
    TokenPrincipal,
};
use service_users_support::{
    install_test_gate, install_test_scopes, scope, seed_service_user, seed_user, MAGNON_READ,
    SUPER, TEST_SCOPES,
};
use support::{system_valence, user_valence};
use valence::{Actor, Model, RecordId, Valence};

fn setup() {
    install_test_gate();
    install_test_scopes();
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
}

fn new_token(label: &str) -> NewPersonalToken<'_> {
    NewPersonalToken {
        label,
        scopes: &MAGNON_READ,
        lifetime: TokenLifetime::Days30,
    }
}

/// A signed-in person with a seeded user row.
async fn person(sys: &Valence, id: &str) -> Valence {
    seed_user(sys, id).await;
    user_valence(sys, id)
}

/// Raw stored row, bypassing privacy.
async fn stored_token(sys: &Valence, id: &str) -> Option<serde_json::Value> {
    let backend = sys.backend_for_table("personal_token").expect("backend");
    valence::get_record(backend.as_ref(), "personal_token", id, valence::use_!(r"**Test:** Fixture read of a **personal token** row so the suite can assert what was stored, independent of privacy. CI and developers running the suite only."))
        .await
        .expect("raw read")
}

fn token_id(row: &TokenRow) -> String {
    row.id().expect("id").id().to_string()
}

#[tokio::test]
async fn create_list_verify_happy() {
    setup();
    let sys = system_valence("pt_happy").await;
    let alice = person(&sys, "pt-alice").await;

    let created = create_personal_token(
        &alice,
        NewPersonalToken {
            label: "Laptop CLI",
            scopes: &[scope("magnon:write"), scope("magnon:read")],
            lifetime: TokenLifetime::Days90,
        },
    )
    .await
    .expect("create");
    assert!(created.token.starts_with("lptk_"));
    let days = (*created.row.expires_at() - Utc::now()).num_days();
    assert!((89..=90).contains(&days), "90-day lifetime, got {days}");

    let verified = verify_bearer_token(&created.token, &sys)
        .await
        .expect("verify");
    assert_eq!(
        verified.principal,
        TokenPrincipal::Person(Actor::User {
            user_id: "pt-alice".into()
        })
    );
    assert_eq!(
        verified.scopes,
        [scope("magnon:read"), scope("magnon:write")]
    );
    assert!(!verified.has_scope(&scope("spectra:read")));

    let listed = list_personal_tokens(&alice).await.expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].label(), "Laptop CLI");

    // The row never holds the plaintext secret.
    let secret = created.token.rsplit('_').next().expect("secret");
    let stored = stored_token(&sys, &token_id(&created.row))
        .await
        .expect("row")
        .to_string();
    assert!(!stored.contains(secret));
    assert!(!format!("{created:?}").contains(secret));
}

#[tokio::test]
async fn a_person_reads_only_their_own_tokens_sad() {
    setup();
    let sys = system_valence("pt_privacy").await;
    let alice = person(&sys, "pt-priv-alice").await;
    let created = create_personal_token(&alice, new_token("cli"))
        .await
        .expect("create");
    let id = token_id(&created.row);

    // Another person, a manage-any user included, sees none of them and cannot revoke.
    for other in ["pt-priv-bob", &format!("{SUPER}-pt")] {
        let other = person(&sys, other).await;
        assert!(list_personal_tokens(&other).await.expect("list").is_empty());
        assert!(matches!(
            revoke_personal_token(&other, &id).await,
            Err(PersonalTokenError::NotFound)
        ));
        let direct = TokenRow::get(&id, &other, valence::use_!(r"**Test:** Attempt to read another person's **personal token** directly, which must return nothing. CI and developers running the suite only."))
            .await;
        assert!(!matches!(direct, Ok(Some(_))), "foreign row is hidden");
    }
    assert!(verify_bearer_token(&created.token, &sys).await.is_some());
}

#[tokio::test]
async fn nobody_saves_a_token_for_someone_else_sad() {
    setup();
    let sys = system_valence("pt_forged").await;
    let _victim = person(&sys, "pt-victim").await;
    let evil = person(&sys, "pt-evil").await;
    let row = TokenRow::new(
        RecordId::new("user", "pt-victim"),
        "forged".into(),
        LeptonToken::generate().hash(),
        scopes_to_json(&MAGNON_READ),
        Utc::now() + Duration::days(1),
        None,
        None,
        Utc::now(),
    )
    .expect("row");
    let saved = TokenRow::upsert("forged-id", row, &evil, valence::use_!(r"**Test:** Attempt to save a **personal token** for another person, which must be refused. CI and developers running the suite only."))
        .await;
    assert!(saved.is_err(), "create is owner-only");
}

#[tokio::test]
async fn a_service_user_has_no_personal_tokens_sad() {
    setup();
    let sys = system_valence("pt_service_user").await;
    let (_, id, _) = seed_service_user(&sys, "maker-pt-su", "pt-su").await;
    let as_service_user = sys.with_actor(id.actor());
    assert!(matches!(
        create_personal_token(&as_service_user, new_token("x")).await,
        Err(PersonalTokenError::NotAUser)
    ));
    assert!(matches!(
        list_personal_tokens(&as_service_user).await,
        Err(PersonalTokenError::NotAUser)
    ));
}

#[tokio::test]
async fn bad_label_or_scopes_refused_sad() {
    setup();
    let sys = system_valence("pt_validation").await;
    let alice = person(&sys, "pt-valid").await;
    for label in ["", "  ", &"x".repeat(81)] {
        assert!(matches!(
            create_personal_token(&alice, new_token(label)).await,
            Err(PersonalTokenError::InvalidProfile { field: "label" })
        ));
    }
    let unregistered = [scope("billing:write")];
    for scopes in [&[][..], &unregistered[..]] {
        assert!(matches!(
            create_personal_token(
                &alice,
                NewPersonalToken {
                    scopes,
                    ..new_token("cli")
                }
            )
            .await,
            Err(PersonalTokenError::InvalidProfile { field: "scopes" })
        ));
    }
    assert!(list_personal_tokens(&alice).await.expect("list").is_empty());
}

#[tokio::test]
async fn revoked_token_refused_sad() {
    setup();
    let sys = system_valence("pt_revoked").await;
    let alice = person(&sys, "pt-revoke").await;
    let created = create_personal_token(&alice, new_token("cli"))
        .await
        .expect("create");
    let id = token_id(&created.row);
    let revoked = revoke_personal_token(&alice, &id).await.expect("revoke");
    let first = *revoked.revoked_at().expect("revoked");
    assert!(verify_bearer_token(&created.token, &sys).await.is_none());
    // Revoking twice is fine and keeps the first time.
    let again = revoke_personal_token(&alice, &id)
        .await
        .expect("revoke again");
    assert_eq!(again.revoked_at(), Some(&first));
}

#[tokio::test]
async fn expired_token_refused_sad() {
    setup();
    let sys = system_valence("pt_expired").await;
    let alice = person(&sys, "pt-expired").await;
    let token = LeptonToken::generate();
    let row = TokenRow::new(
        RecordId::new("user", "pt-expired"),
        "old".into(),
        token.hash(),
        scopes_to_json(&MAGNON_READ),
        Utc::now() - Duration::seconds(10),
        None,
        None,
        Utc::now() - Duration::days(31),
    )
    .expect("row");
    TokenRow::upsert(token.id(), row, &alice, valence::use_!(r"**Test:** Fixture save of an already expired **personal token** so the suite can check expiry is enforced. CI and developers running the suite only."))
        .await
        .expect("seed expired token");
    assert!(verify_bearer_token(&token.expose(), &sys).await.is_none());
    // An expired token does not count toward the limit, but is still listed.
    assert_eq!(list_personal_tokens(&alice).await.expect("list").len(), 1);
}

#[tokio::test]
async fn disabled_person_refused_sad() {
    setup();
    let sys = system_valence("pt_disabled").await;
    let alice = person(&sys, "pt-disabled").await;
    let created = create_personal_token(&alice, new_token("cli"))
        .await
        .expect("create");
    let user = User::get("pt-disabled", &sys, valence::use_!(r"**Test:** Fixture read of a **User** so the suite can disable it. CI and developers running the suite only."))
        .await
        .expect("read")
        .expect("user");
    user.get_mutable(&sys, valence::use_!(r"**Test:** Fixture change of a **User** status so the suite can check a disabled person's tokens stop working. CI and developers running the suite only."))
        .set_status(UserStatus::Disabled)
        .expect("set")
        .commit()
        .await
        .expect("disable");
    assert!(verify_bearer_token(&created.token, &sys).await.is_none());
}

#[tokio::test]
async fn token_limit_sad() {
    setup();
    let sys = system_valence("pt_limit").await;
    let alice = person(&sys, "pt-limit").await;
    let mut first = None;
    for i in 0..MAX_PERSONAL_TOKENS {
        let t = create_personal_token(&alice, new_token(&format!("t{i}")))
            .await
            .expect("under limit");
        first.get_or_insert(t);
    }
    assert_eq!(MAX_PERSONAL_TOKENS, 25);
    assert!(matches!(
        create_personal_token(&alice, new_token("over")).await,
        Err(PersonalTokenError::QuotaReached { limit: 25 })
    ));
    // Revoking frees a slot.
    let first = first.expect("first");
    revoke_personal_token(&alice, &token_id(&first.row))
        .await
        .expect("revoke");
    create_personal_token(&alice, new_token("again"))
        .await
        .expect("slot freed");
}

#[tokio::test]
async fn owner_cannot_widen_or_rehash_a_token_sad() {
    setup();
    let sys = system_valence("pt_immutable").await;
    let alice = person(&sys, "pt-immut").await;
    let created = create_personal_token(&alice, new_token("cli"))
        .await
        .expect("create");

    let widen = created
        .row
        .get_mutable(&alice, valence::use_!(r"**Test:** Attempt to widen the scopes of a **personal token**, which must be refused. CI and developers running the suite only."))
        .set_scopes(scopes_to_json(&TEST_SCOPES))
        .expect("set")
        .commit()
        .await;
    assert!(widen.is_err(), "scopes are immutable");

    let extend = created
        .row
        .get_mutable(&alice, valence::use_!(r"**Test:** Attempt to push out the expiry of a **personal token**, which must be refused. CI and developers running the suite only."))
        .set_expires_at(Utc::now() + Duration::days(365))
        .expect("set")
        .commit()
        .await;
    assert!(extend.is_err(), "expires_at is immutable");

    let rehash = created
        .row
        .get_mutable(&alice, valence::use_!(r"**Test:** Attempt to replace the secret hash of a **personal token**, which must be refused. CI and developers running the suite only."))
        .set_token_hash("0".repeat(64))
        .expect("set")
        .commit()
        .await;
    assert!(rehash.is_err(), "token_hash is immutable");

    let verified = verify_bearer_token(&created.token, &sys)
        .await
        .expect("still verifies");
    assert_eq!(verified.scopes, *MAGNON_READ);
}

#[tokio::test]
async fn last_use_is_recorded_as_the_person() {
    setup();
    let sys = system_valence("pt_touch").await;
    let alice = person(&sys, "pt-touch").await;
    let created = create_personal_token(&alice, new_token("cli"))
        .await
        .expect("create");
    let verified = verify_bearer_token(&created.token, &sys)
        .await
        .expect("verify");
    assert!(verified.last_used_at.is_none());
    record_token_use(&verified, &sys, &alice)
        .await
        .expect("record use");
    let listed = list_personal_tokens(&alice).await.expect("list");
    assert!(listed[0].last_used_at().is_some());

    // Someone else cannot write it.
    let bob = person(&sys, "pt-touch-bob").await;
    assert!(record_token_use(&verified, &sys, &bob).await.is_err());
}

#[tokio::test]
async fn deleting_the_person_removes_their_tokens() {
    setup();
    let sys = system_valence("pt_delete").await;
    let alice = person(&sys, "pt-delete").await;
    let created = create_personal_token(&alice, new_token("cli"))
        .await
        .expect("create");
    lepton_auth::identity_delete::delete_user(&sys, &RecordId::new("user", "pt-delete"))
        .await
        .expect("erase person");
    assert!(verify_bearer_token(&created.token, &sys).await.is_none());
    assert!(
        stored_token(&sys, &token_id(&created.row)).await.is_none(),
        "token row removed with its person"
    );
}
