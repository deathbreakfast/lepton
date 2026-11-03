//! `User` and `Account` protected fields: the owner can edit allowed fields but cannot change
//! status, plan, verification stamps, or the password hash. System can.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use crate::support;

use chrono::Utc;
use lepton_host_adapter::auth::hash_password;
use lepton_host_adapter::generated::{
    Account, AccountPlan, AccountStatus, User, UserStatus, UserUserType,
};
use lepton_identity::ownership::bare_id_from_record;
use support::{system_valence, user_valence};
use valence::Model;

macro_rules! purpose {
    () => {
        valence::use_!(r"**Test:** Fixture save for `tests` so the suite can arrange and assert protected-field update rules. CI and developers running the suite only.")
    };
}

struct Seeded {
    user: String,
    account: String,
    phc: String,
}

async fn seed(sys: &valence::Valence) -> Seeded {
    let now = Utc::now();
    let phc = hash_password("CorrectHorseBattery1!").expect("hash");
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
    let user = User::create(user, sys, purpose!())
        .await
        .expect("create user");
    let user_id = user.id().cloned().expect("user id");
    let account = Account::new(
        "protected".into(),
        user_id.clone(),
        Some(AccountPlan::Free),
        Some(AccountStatus::Active),
        None,
        None,
        now,
        now,
    )
    .expect("account");
    let account = Account::create(account, sys, purpose!())
        .await
        .expect("create account");
    Seeded {
        user: bare_id_from_record(&user_id),
        account: bare_id_from_record(account.id().expect("account id")),
        phc,
    }
}

async fn load_user(v: &valence::Valence, id: &str) -> User {
    User::get(id, v, purpose!())
        .await
        .expect("get")
        .expect("user")
}

async fn load_account(v: &valence::Valence, id: &str) -> Account {
    Account::get(id, v, purpose!())
        .await
        .expect("get")
        .expect("account")
}

#[tokio::test]
async fn owner_edits_allowed_fields_happy_path() {
    let sys = system_valence("protected_allowed").await;
    let s = seed(&sys).await;
    let owner = user_valence(&sys, &s.user);
    let now = Utc::now();

    load_user(&owner, &s.user)
        .await
        .get_mutable(&owner, purpose!())
        .set_last_login_at(now)
        .expect("set")
        .set_updated_at(now)
        .expect("set")
        .commit()
        .await
        .expect("owner edits last_login_at");
    assert!(load_user(&sys, &s.user).await.last_login_at().is_some());

    load_account(&owner, &s.account)
        .await
        .get_mutable(&owner, purpose!())
        .set_name("renamed".into())
        .expect("set")
        .commit()
        .await
        .expect("owner renames account");
    assert_eq!(load_account(&sys, &s.account).await.name(), "renamed");
}

#[tokio::test]
async fn session_edit_does_not_null_password_hash_happy_path() {
    let sys = system_valence("protected_null_hash").await;
    let s = seed(&sys).await;
    let owner = user_valence(&sys, &s.user);
    let loaded = load_user(&owner, &s.user).await;
    assert!(loaded.password_hash().is_none(), "owner copy is redacted");

    loaded
        .get_mutable(&owner, purpose!())
        .set_last_login_at(Utc::now())
        .expect("set")
        .commit()
        .await
        .expect("owner edit");

    let stored = load_user(&sys, &s.user).await;
    assert_eq!(stored.password_hash(), Some(&s.phc));
}

macro_rules! denied_user_change {
    ($name:ident, $setter:ident, $value:expr, $check:expr) => {
        #[tokio::test]
        async fn $name() {
            let sys = system_valence(stringify!($name)).await;
            let s = seed(&sys).await;
            let owner = user_valence(&sys, &s.user);
            let result = load_user(&owner, &s.user)
                .await
                .get_mutable(&owner, purpose!())
                .$setter($value)
                .expect("set")
                .commit()
                .await;
            assert!(result.is_err(), "owner must not change this field");
            let check: fn(&User) -> bool = $check;
            assert!(
                check(&load_user(&sys, &s.user).await),
                "stored value unchanged"
            );
        }
    };
}

denied_user_change!(
    owner_cannot_change_user_status_sad,
    set_status,
    UserStatus::Disabled,
    |u| { u.status() == Some(&UserStatus::Active) }
);
denied_user_change!(
    owner_cannot_change_user_type_sad,
    set_user_type,
    UserUserType::Service,
    |u| { u.user_type() == Some(&UserUserType::Person) }
);
denied_user_change!(
    owner_cannot_set_confirmed_at_sad,
    set_confirmed_at,
    Utc::now(),
    |u| { u.confirmed_at().is_none() }
);
denied_user_change!(
    owner_cannot_set_id_verified_at_sad,
    set_id_verified_at,
    Utc::now(),
    |u| { u.id_verified_at().is_none() }
);

#[tokio::test]
async fn owner_cannot_change_password_hash_sad() {
    let sys = system_valence("protected_hash_denied").await;
    let s = seed(&sys).await;
    let owner = user_valence(&sys, &s.user);
    let forged = hash_password("AttackerChosen1!").expect("hash");
    let result = load_user(&owner, &s.user)
        .await
        .get_mutable(&owner, purpose!())
        .set_password_hash(forged)
        .expect("set")
        .commit()
        .await;
    assert!(result.is_err());
    assert_eq!(load_user(&sys, &s.user).await.password_hash(), Some(&s.phc));
}

#[tokio::test]
async fn owner_cannot_change_account_plan_or_status_sad() {
    let sys = system_valence("protected_account_denied").await;
    let s = seed(&sys).await;
    let owner = user_valence(&sys, &s.user);

    let plan = load_account(&owner, &s.account)
        .await
        .get_mutable(&owner, purpose!())
        .set_plan(AccountPlan::Enterprise)
        .expect("set")
        .commit()
        .await;
    assert!(plan.is_err(), "plan");
    let status = load_account(&owner, &s.account)
        .await
        .get_mutable(&owner, purpose!())
        .set_status(AccountStatus::Cancelled)
        .expect("set")
        .commit()
        .await;
    assert!(status.is_err(), "status");

    let stored = load_account(&sys, &s.account).await;
    assert_eq!(stored.plan(), Some(&AccountPlan::Free));
    assert_eq!(stored.status(), Some(&AccountStatus::Active));
}

#[tokio::test]
async fn system_can_change_protected_fields_happy_path() {
    let sys = system_valence("protected_system").await;
    let s = seed(&sys).await;
    let now = Utc::now();
    let new_hash = hash_password("SystemChosen1!").expect("hash");

    load_user(&sys, &s.user)
        .await
        .get_mutable(&sys, purpose!())
        .set_status(UserStatus::Disabled)
        .expect("set")
        .set_user_type(UserUserType::Service)
        .expect("set")
        .set_confirmed_at(now)
        .expect("set")
        .set_id_verified_at(now)
        .expect("set")
        .set_password_hash(new_hash.clone())
        .expect("set")
        .commit()
        .await
        .expect("system writes protected user fields");
    let user = load_user(&sys, &s.user).await;
    assert_eq!(user.status(), Some(&UserStatus::Disabled));
    assert_eq!(user.password_hash(), Some(&new_hash));
    assert!(user.confirmed_at().is_some() && user.id_verified_at().is_some());

    load_account(&sys, &s.account)
        .await
        .get_mutable(&sys, purpose!())
        .set_plan(AccountPlan::Enterprise)
        .expect("set")
        .set_status(AccountStatus::Suspended)
        .expect("set")
        .commit()
        .await
        .expect("system writes protected account fields");
    let account = load_account(&sys, &s.account).await;
    assert_eq!(account.plan(), Some(&AccountPlan::Enterprise));
    assert_eq!(account.status(), Some(&AccountStatus::Suspended));
}

#[tokio::test]
async fn peer_cannot_edit_other_users_row_sad() {
    let sys = system_valence("protected_peer").await;
    let a = seed(&sys).await;
    let b = seed(&sys).await;
    let bob = user_valence(&sys, &b.user);
    let result = load_user(&sys, &a.user)
        .await
        .get_mutable(&bob, purpose!())
        .set_last_login_at(Utc::now())
        .expect("set")
        .commit()
        .await;
    assert!(result.is_err());
}
