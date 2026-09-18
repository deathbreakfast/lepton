//! `User.password_hash` field read: owner allow, cross-user redact, System preserve.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

use chrono::Utc;
use lepton_host_adapter::auth::hash_password;
use lepton_host_adapter::generated::{User, UserStatus, UserUserType};
use lepton_identity::ownership::bare_id_from_record;
use support::{system_valence, user_valence};
use valence::Model;

struct SeededUser {
    bare: String,
    phc: String,
}

async fn seed_user_with_password(valence: &valence::Valence, password: &str) -> SeededUser {
    let phc = hash_password(password).expect("hash");
    let now = Utc::now();
    let user = User::new(
        Some(UserUserType::Person),
        Some(phc.clone()),
        Some(UserStatus::Active),
        None,
        None,
        None,
        None,
        None,
        now,
        now,
    )
    .expect("user");
    let created = User::create_used(user, valence, valence::use_!(r"**Test:** Fixture **User** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only.")).await.expect("create user");
    let id = created.id().cloned().expect("user id");
    let bare = bare_id_from_record(&id);
    SeededUser { bare, phc }
}

#[tokio::test]
async fn password_hash_owner_read_happy_path() {
    let sys = system_valence("password_hash_owner_read").await;
    let alice = seed_user_with_password(&sys, "AlicePassword1!").await;
    let bob = seed_user_with_password(&sys, "BobPassword1!!").await;

    let alice_v = user_valence(&sys, &alice.bare);
    let loaded = User::get_used(&alice.bare, &alice_v, valence::use_!(r"**Test:** Fixture **User** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("get")
        .expect("alice row");
    assert_eq!(loaded.password_hash(), Some(&alice.phc));

    // Harness sanity: peer can still read their own PHC.
    let bob_v = user_valence(&sys, &bob.bare);
    let bob_self = User::get_used(&bob.bare, &bob_v, valence::use_!(r"**Test:** Fixture **User** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("get bob")
        .expect("bob row");
    assert_eq!(bob_self.password_hash(), Some(&bob.phc));
}

#[tokio::test]
async fn password_hash_cross_user_redacted_sad() {
    let sys = system_valence("password_hash_cross_user").await;
    let alice = seed_user_with_password(&sys, "AlicePassword1!").await;
    let bob = seed_user_with_password(&sys, "BobPassword1!!").await;

    let bob_v = user_valence(&sys, &bob.bare);
    let alice_as_bob = User::get_used(&alice.bare, &bob_v, valence::use_!(r"**Test:** Fixture **User** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("get alice as bob")
        .expect("entity still readable");
    assert!(
        alice_as_bob.password_hash().is_none(),
        "Bob must not see Alice's password_hash"
    );

    let alice_v = user_valence(&sys, &alice.bare);
    let bob_as_alice = User::get_used(&bob.bare, &alice_v, valence::use_!(r"**Test:** Fixture **User** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("get bob as alice")
        .expect("entity still readable");
    assert!(
        bob_as_alice.password_hash().is_none(),
        "Alice must not see Bob's password_hash"
    );

    // Peer still sees own PHC (actor wiring works).
    let bob_self = User::get_used(&bob.bare, &bob_v, valence::use_!(r"**Test:** Fixture **User** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("get bob self")
        .expect("bob row");
    assert_eq!(bob_self.password_hash(), Some(&bob.phc));
}

#[tokio::test]
async fn password_hash_system_read_happy_path() {
    let sys = system_valence("password_hash_system_read").await;
    let alice = seed_user_with_password(&sys, "AlicePassword1!").await;
    let bob = seed_user_with_password(&sys, "BobPassword1!!").await;

    let alice_row = User::get_used(&alice.bare, &sys, valence::use_!(r"**Test:** Fixture **User** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("get alice")
        .expect("alice");
    assert_eq!(alice_row.password_hash(), Some(&alice.phc));

    let bob_row = User::get_used(&bob.bare, &sys, valence::use_!(r"**Test:** Fixture **User** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("get bob")
        .expect("bob");
    assert_eq!(bob_row.password_hash(), Some(&bob.phc));
}
