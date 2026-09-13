//! `AccountEmail` owner denial: non-owner User cannot read; owner and System can.
//!
//! Entity read uses `defer_to_edge: "account"` (owner via Account.user). Address
//! has no field-level policy so owners who pass entity defer can deserialize it.

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
    let user = User::create_used(user, valence, valence::use_!("create User in lepton-auth/tests/account_email_owner_privacy.rs; Valence persistence for this feature path; typed store; visible to test harness.")).await.expect("create user");
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
    let account = Account::create_used(account, valence, valence::use_!("create Account in lepton-auth/tests/account_email_owner_privacy.rs; Valence persistence for this feature path; typed store; visible to test harness.")).await.expect("account");
    let account_id = account.id().cloned().expect("account id");

    AccountMembership::create_used(
        AccountMembership::new(
            account_id.clone(),
            user_id.clone(),
            AccountMembershipRole::Owner,
            now,
            now,
        )
        .expect("m"),
        valence,
        valence::use_!("create AccountMembership in lepton-auth/tests/account_email_owner_privacy.rs; Valence persistence for this feature path; typed store; visible to test harness."),
    )
    .await
    .expect("membership");

    let email = AccountEmail::new(account_id, "owner@example.test".into(), Some(now), now, now)
        .expect("email");
    let email = AccountEmail::create_used(email, valence, valence::use_!("create AccountEmail in lepton-auth/tests/account_email_owner_privacy.rs; Valence persistence for this feature path; typed store; visible to test harness.")).await.expect("email");
    let email_bare = bare_id_from_record(email.id().expect("email id"));

    (owner_bare, email_bare, "owner@example.test".into())
}

#[tokio::test]
async fn account_email_system_can_read_address_happy() {
    let sys = system_valence("email_system_read").await;
    let (_owner_bare, email_bare, address) = seed_owner_with_email(&sys).await;

    let row = AccountEmail::get_used(&email_bare, &sys, valence::use_!("get AccountEmail in lepton-auth/tests/account_email_owner_privacy.rs; Valence persistence for this feature path; typed store; visible to test harness."))
        .await
        .expect("get")
        .expect("System always_allow may read email");
    assert_eq!(row.address(), address.as_str());
}

#[tokio::test]
async fn account_email_owner_can_read_address_happy() {
    let sys = system_valence("email_owner_read").await;
    let (owner_bare, email_bare, address) = seed_owner_with_email(&sys).await;
    let owner_v = user_valence(&sys, &owner_bare);

    let row = AccountEmail::get_used(&email_bare, &owner_v, valence::use_!("get AccountEmail in lepton-auth/tests/account_email_owner_privacy.rs; Valence persistence for this feature path; typed store; visible to test harness."))
        .await
        .expect("get")
        .expect("owner must read own email after entity defer");
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
    let peer = User::create_used(peer, &sys, valence::use_!("create User in lepton-auth/tests/account_email_owner_privacy.rs; Valence persistence for this feature path; typed store; visible to test harness.")).await.expect("create peer");
    let peer_bare = bare_id_from_record(peer.id().expect("id"));
    let peer_v = user_valence(&sys, &peer_bare);

    let denied = AccountEmail::get_used(&email_bare, &peer_v, valence::use_!("get AccountEmail in lepton-auth/tests/account_email_owner_privacy.rs; Valence persistence for this feature path; typed store; visible to test harness.")).await;
    match denied {
        Ok(None) | Err(_) => {}
        Ok(Some(row)) => panic!(
            "peer must not read owner email address, got {}",
            row.address()
        ),
    }
}
