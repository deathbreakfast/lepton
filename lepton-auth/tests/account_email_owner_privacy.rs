//! AccountEmail owner denial: non-owner User cannot read; System can (always_allow).
//!
//! Entity read uses `defer_to_edge: "account"` (owner via Account.user). Field-level
//! `address` policies still evaluate sync buckets only — `SYSTEM_ONLY` always_allow —
//! so owner User can pass entity defer but may not deserialize `address` until Valence
//! field filtering honors defer. This suite validates peer denial + System read.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

use chrono::Utc;
use lepton_host_adapter::auth::hash_password;
use lepton_host_adapter::generated::{
    Account, AccountEmail, AccountMembership, AccountMembershipRole, AccountPlan, AccountStatus,
    User, UserStatus, UserUserType,
};
use lepton_identity::ownership::bare_id_from_record;
use support::{system_valence, user_valence};
use valence::Model;

async fn seed_owner_with_email(valence: &valence::Valence) -> (String, String, String) {
    let now = Utc::now();
    let user = User::new(
        Some(UserUserType::Person),
        Some(hash_password("CorrectHorseBattery1!").expect("hash")),
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
    let user = User::create(user, valence).await.expect("create user");
    let user_id = user.id().cloned().expect("user id");
    let owner_bare = bare_id_from_record(&user_id);

    let account = Account::new(
        "email-privacy".into(),
        user_id.clone(),
        Some(AccountPlan::Free),
        Some(AccountStatus::Active),
        None,
        None,
        now,
        now,
    )
    .expect("account");
    let account = Account::create(account, valence).await.expect("account");
    let account_id = account.id().cloned().expect("account id");

    AccountMembership::create(
        AccountMembership::new(
            account_id.clone(),
            user_id.clone(),
            AccountMembershipRole::Owner,
            now,
            now,
        )
        .expect("m"),
        valence,
    )
    .await
    .expect("membership");

    let email = AccountEmail::new(account_id, "owner@example.test".into(), Some(now), now, now)
        .expect("email");
    let email = AccountEmail::create(email, valence).await.expect("email");
    let email_bare = bare_id_from_record(email.id().expect("email id"));

    (owner_bare, email_bare, "owner@example.test".into())
}

#[tokio::test]
async fn account_email_system_can_read_address_happy() {
    let sys = system_valence("email_system_read").await;
    let (_owner_bare, email_bare, address) = seed_owner_with_email(&sys).await;

    let row = AccountEmail::get(&email_bare, &sys)
        .await
        .expect("get")
        .expect("System always_allow may read email");
    assert_eq!(row.address(), address.as_str());
}

#[tokio::test]
async fn account_email_peer_cannot_read_address_sad() {
    let sys = system_valence("email_peer_deny").await;
    let (_owner_bare, email_bare, _) = seed_owner_with_email(&sys).await;

    let now = Utc::now();
    let peer = User::new(
        Some(UserUserType::Person),
        Some(hash_password("CorrectHorseBattery1!").expect("hash")),
        Some(UserStatus::Active),
        None,
        None,
        None,
        None,
        None,
        now,
        now,
    )
    .expect("peer");
    let peer = User::create(peer, &sys).await.expect("create peer");
    let peer_bare = bare_id_from_record(peer.id().expect("id"));
    let peer_v = user_valence(&sys, &peer_bare);

    let denied = AccountEmail::get(&email_bare, &peer_v).await;
    match denied {
        Ok(None) => {}
        Err(_) => {}
        Ok(Some(row)) => panic!(
            "peer must not read owner email address, got {}",
            row.address()
        ),
    }
}
