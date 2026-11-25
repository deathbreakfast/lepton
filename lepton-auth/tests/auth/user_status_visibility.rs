//! `User.status` read: any signed-in user can tell whether another user is active.
//! Anonymous callers still see nothing, and the other owner-only fields stay hidden.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use crate::support;

use chrono::Utc;
use lepton_host_adapter::generated::{User, UserStatus, UserUserType};
use lepton_identity::ownership::bare_id_from_record;
use support::{system_valence, user_valence};
use valence::{Actor, Model};

async fn seed_user(valence: &valence::Valence, status: UserStatus) -> String {
    let now = Utc::now();
    let user = User::new(
        Some(UserUserType::Person),
        None,
        Some(status),
        None,
        None,
        None,
        None,
        Some(now),
        now,
        now,
    )
    .expect("user");
    let created = User::create(user, valence, valence::use_!(r"**Test:** the user status visibility suite seeds **users** with a known status so it can check who can read it."))
        .await
        .expect("create user");
    bare_id_from_record(created.id().expect("user id"))
}

#[tokio::test]
async fn signed_in_user_reads_peer_status_happy_path() {
    let sys = system_valence("user_status_peer_read").await;
    let alice = seed_user(&sys, UserStatus::Disabled).await;
    let bob = seed_user(&sys, UserStatus::Active).await;

    let bob_v = user_valence(&sys, &bob);
    let alice_as_bob = User::get(&alice, &bob_v, valence::use_!(r"**Test:** the user status visibility suite **loads another user** as a signed-in peer to check that their status is readable."))
        .await
        .expect("get alice as bob")
        .expect("row readable to a signed-in user");
    assert_eq!(alice_as_bob.status(), Some(&UserStatus::Disabled));
}

#[tokio::test]
async fn peer_still_cannot_read_other_owner_only_fields_sad() {
    let sys = system_valence("user_status_peer_hidden").await;
    let alice = seed_user(&sys, UserStatus::Active).await;
    let bob = seed_user(&sys, UserStatus::Active).await;

    let bob_v = user_valence(&sys, &bob);
    let alice_as_bob = User::get(&alice, &bob_v, valence::use_!(r"**Test:** the user status visibility suite **loads another user** as a signed-in peer to check that owner-only fields stay hidden."))
        .await
        .expect("get alice as bob")
        .expect("row readable to a signed-in user");
    assert!(
        alice_as_bob.last_login_at().is_none(),
        "last_login_at is owner-only"
    );
    assert!(
        alice_as_bob.user_type().is_none(),
        "user_type is owner-only"
    );
}

#[tokio::test]
async fn anonymous_cannot_read_user_status_sad() {
    let sys = system_valence("user_status_anonymous").await;
    let alice = seed_user(&sys, UserStatus::Disabled).await;

    let anon = sys.with_actor(Actor::Anonymous);
    let row = User::get(&alice, &anon, valence::use_!(r"**Test:** the user status visibility suite **loads a user** with no session to check that nothing is readable."))
        .await
        .expect("get as anonymous");
    assert!(
        row.as_ref().and_then(User::status).is_none(),
        "anonymous callers must not read status"
    );
}
