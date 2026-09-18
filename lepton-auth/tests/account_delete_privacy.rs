//! Account delete privacy: `OWNER_BY_USER_FIELD` (TM-D1, TM-D4) + peer deny (TM-D2).
//!
//! Uses [`Account::delete`] with a noop deletion dispatcher so privacy runs before queue.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

use chrono::Utc;
use lepton_host_adapter::auth::hash_password;
use lepton_host_adapter::generated::{
    Account, AccountMembership, AccountMembershipRole, AccountPlan, AccountStatus, User,
    UserStatus, UserUserType,
};
use lepton_identity::ownership::bare_id_from_record;
use support::{system_valence, user_valence};
use valence::{Actor, Model, RecordId};

fn ensure_deletion_dispatcher() {
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
}

async fn seed_owner_account(valence: &valence::Valence) -> (RecordId, RecordId, String) {
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
    let user = User::create_used(user, valence, valence::use_!(r"**Test:** Fixture **User** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only.")).await.expect("create");
    let user_id = user.id().cloned().expect("id");
    let bare = bare_id_from_record(&user_id);

    let account = Account::new(
        "delete-privacy".into(),
        user_id.clone(),
        Some(AccountPlan::Free),
        Some(AccountStatus::Active),
        None,
        None,
        now,
        now,
    )
    .expect("account");
    let account = Account::create_used(account, valence, valence::use_!(r"**Test:** Fixture **Account** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only.")).await.expect("account");
    let account_id = account.id().cloned().expect("id");

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
        valence::use_!(r"**Test:** Fixture **Account Membership** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."),
    )
    .await
    .expect("membership");

    (user_id, account_id, bare)
}

#[tokio::test]
async fn account_delete_owner_valence_happy() {
    ensure_deletion_dispatcher();
    let sys = system_valence("acct_del_owner").await;
    let (_user, account, bare) = seed_owner_account(&sys).await;
    let owner_v = user_valence(&sys, &bare);

    Account::delete_used(&bare_id_from_record(&account), &owner_v, valence::use_!(r"**Test:** Fixture **Account** remove for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("founding user may delete");
}

#[tokio::test]
async fn account_delete_peer_denied_sad() {
    ensure_deletion_dispatcher();
    let sys = system_valence("acct_del_peer").await;
    let (_owner, account, _owner_bare) = seed_owner_account(&sys).await;

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
    let peer = User::create_used(peer, &sys, valence::use_!(r"**Test:** Fixture **User** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only.")).await.expect("create");
    let peer_bare = bare_id_from_record(peer.id().expect("id"));

    AccountMembership::create_used(
        AccountMembership::new(
            account.clone(),
            peer.id().cloned().expect("id"),
            AccountMembershipRole::Admin,
            now,
            now,
        )
        .expect("m"),
        &sys,
        valence::use_!(r"**Test:** Fixture **Account Membership** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."),
    )
    .await
    .expect("membership");

    let peer_v = user_valence(&sys, &peer_bare);
    Account::delete_used(&bare_id_from_record(&account), &peer_v, valence::use_!(r"**Test:** Fixture **Account** remove for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect_err("peer cannot delete");
    assert!(Account::get_used(&bare_id_from_record(&account), &sys, valence::use_!(r"**Test:** Fixture **Account** remove for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("get")
        .is_some());
}

#[tokio::test]
async fn account_delete_unauth_denied_sad() {
    ensure_deletion_dispatcher();
    let sys = system_valence("acct_del_anon").await;
    let (_user, account, _) = seed_owner_account(&sys).await;
    let anon_v = sys.with_actor(Actor::Anonymous);

    Account::delete_used(&bare_id_from_record(&account), &anon_v, valence::use_!(r"**Test:** Fixture **Account** remove for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect_err("anonymous cannot delete");
    assert!(Account::get_used(&bare_id_from_record(&account), &sys, valence::use_!(r"**Test:** Fixture **Account** remove for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("get")
        .is_some());
}
