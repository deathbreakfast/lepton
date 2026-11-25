//! Product erase hooks run before the user delete (`lepton_auth::erase_hooks`).
//!
//! The registry is process-wide, so this binary's tests take turns.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::Utc;
use lepton_auth::erase_hooks::{
    register_user_erase_hook, unregister_user_erase_hook, UserEraseHook, UserEraseHookError,
};
use lepton_auth::identity_delete::{delete_user, erase_account, IdentityDeleteError};
use lepton_host_adapter::auth::hash_password;
use lepton_host_adapter::generated::{
    Account, AccountMembership, AccountMembershipRole, AccountPlan, AccountStatus, User,
    UserStatus, UserUserType,
};
use lepton_identity::ownership::bare_id_from_record;
use support::system_valence;
use valence::{Model, RecordId, Valence};

static HOOK_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const NAME: &str = "books";

/// Stands in for a product's personal books: a count per user id, removed by the hook.
#[derive(Default)]
struct Books {
    by_user: Mutex<HashMap<String, usize>>,
    /// Whether the user row still existed when the hook ran, per user id.
    user_present_at_hook: Mutex<HashMap<String, bool>>,
    fail: Mutex<bool>,
}

impl Books {
    fn seed(&self, user: &str, n: usize) {
        self.by_user.lock().unwrap().insert(user.to_string(), n);
    }
    fn count(&self, user: &str) -> usize {
        self.by_user.lock().unwrap().get(user).copied().unwrap_or(0)
    }
    fn set_fail(&self, fail: bool) {
        *self.fail.lock().unwrap() = fail;
    }
}

struct BooksHook(Arc<Books>);

#[async_trait]
impl UserEraseHook for BooksHook {
    fn name(&self) -> &'static str {
        NAME
    }

    async fn erase_user(&self, user_id: &str, valence: &Valence) -> Result<(), UserEraseHookError> {
        let present = User::get(user_id, valence, valence::use_!("**Test:** Fixture **User** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
            .await
            .expect("get user")
            .is_some();
        self.0
            .user_present_at_hook
            .lock()
            .unwrap()
            .insert(user_id.to_string(), present);
        if *self.0.fail.lock().unwrap() {
            return Err(UserEraseHookError::new("books store unavailable"));
        }
        self.0.by_user.lock().unwrap().remove(user_id);
        Ok(())
    }
}

fn install(books: &Arc<Books>) {
    register_user_erase_hook(Arc::new(BooksHook(Arc::clone(books))));
}

async fn seed_user(valence: &Valence) -> RecordId {
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
    User::create(user, valence, valence::use_!("**Test:** Fixture **User** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("create user")
        .id()
        .cloned()
        .expect("user id")
}

async fn seed_account(valence: &Valence, name: &str, user: &RecordId) -> RecordId {
    let now = Utc::now();
    let account = Account::new(
        name.to_string(),
        user.clone(),
        Some(AccountPlan::Free),
        Some(AccountStatus::Active),
        None,
        None,
        now,
        now,
    )
    .expect("account");
    Account::create(account, valence, valence::use_!("**Test:** Fixture **Account** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("create account")
        .id()
        .cloned()
        .expect("account id")
}

async fn seed_membership(
    valence: &Valence,
    account: &RecordId,
    user: &RecordId,
    role: AccountMembershipRole,
) {
    let now = Utc::now();
    let m =
        AccountMembership::new(account.clone(), user.clone(), role, now, now).expect("membership");
    AccountMembership::create(m, valence, valence::use_!("**Test:** Fixture **Account Membership** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("create membership");
}

async fn user_exists(valence: &Valence, user: &RecordId) -> bool {
    User::get(&bare_id_from_record(user), valence, valence::use_!("**Test:** Fixture **User** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("get user")
        .is_some()
}

#[tokio::test]
async fn erase_account_runs_hook_before_user_delete_and_removes_books() {
    let _turn = HOOK_LOCK.lock().await;
    let valence = system_valence("erase_hook_happy").await;
    let books = Arc::new(Books::default());
    install(&books);

    let user = seed_user(&valence).await;
    let uid = bare_id_from_record(&user);
    let account = seed_account(&valence, "erase-hook@example.test", &user).await;
    seed_membership(&valence, &account, &user, AccountMembershipRole::Owner).await;
    books.seed(&uid, 3);

    erase_account(&valence, &account).await.expect("erase");

    assert_eq!(books.count(&uid), 0, "personal books removed");
    assert!(!user_exists(&valence, &user).await, "user removed");
    assert_eq!(
        books.user_present_at_hook.lock().unwrap().get(&uid),
        Some(&true),
        "hook ran while the user row still existed"
    );
    unregister_user_erase_hook(NAME);
}

#[tokio::test]
async fn failing_hook_keeps_the_user_and_a_rerun_succeeds() {
    let _turn = HOOK_LOCK.lock().await;
    let valence = system_valence("erase_hook_fail").await;
    let books = Arc::new(Books::default());
    install(&books);

    let user = seed_user(&valence).await;
    let uid = bare_id_from_record(&user);
    let account = seed_account(&valence, "erase-hook-fail@example.test", &user).await;
    seed_membership(&valence, &account, &user, AccountMembershipRole::Owner).await;
    books.seed(&uid, 2);

    books.set_fail(true);
    let err = erase_account(&valence, &account)
        .await
        .expect_err("hook fails");
    assert!(matches!(err, IdentityDeleteError::EraseHook), "got {err:?}");
    assert_eq!(err.reason_class(), "erase_hook");
    assert!(user_exists(&valence, &user).await, "user kept");
    assert_eq!(books.count(&uid), 2, "books untouched");

    // The failed pass already removed the account and memberships; the retry deletes the user.
    books.set_fail(false);
    delete_user(&valence, &user).await.expect("retry");
    assert_eq!(books.count(&uid), 0);
    assert!(!user_exists(&valence, &user).await);
    unregister_user_erase_hook(NAME);
}

#[tokio::test]
async fn delete_user_runs_hooks_for_a_non_sole_member() {
    let _turn = HOOK_LOCK.lock().await;
    let valence = system_valence("erase_hook_delete_user").await;
    let books = Arc::new(Books::default());
    install(&books);

    let owner = seed_user(&valence).await;
    let persona = seed_user(&valence).await;
    let pid = bare_id_from_record(&persona);
    let account = seed_account(&valence, "erase-hook-persona@example.test", &owner).await;
    seed_membership(&valence, &account, &owner, AccountMembershipRole::Owner).await;
    seed_membership(&valence, &account, &persona, AccountMembershipRole::Admin).await;
    books.seed(&pid, 1);

    delete_user(&valence, &persona)
        .await
        .expect("delete persona");

    assert_eq!(books.count(&pid), 0);
    assert!(!user_exists(&valence, &persona).await);
    assert!(user_exists(&valence, &owner).await, "owner untouched");
    unregister_user_erase_hook(NAME);
}

#[tokio::test]
async fn registering_the_same_name_replaces_the_hook() {
    let _turn = HOOK_LOCK.lock().await;
    let valence = system_valence("erase_hook_replace").await;
    let old = Arc::new(Books::default());
    let new = Arc::new(Books::default());
    install(&old);
    install(&new);

    let owner = seed_user(&valence).await;
    let persona = seed_user(&valence).await;
    let account = seed_account(&valence, "erase-hook-replace@example.test", &owner).await;
    seed_membership(&valence, &account, &owner, AccountMembershipRole::Owner).await;
    seed_membership(&valence, &account, &persona, AccountMembershipRole::Admin).await;
    delete_user(&valence, &persona).await.expect("delete");

    let pid = bare_id_from_record(&persona);
    assert!(
        old.user_present_at_hook.lock().unwrap().get(&pid).is_none(),
        "replaced hook not run"
    );
    assert!(new.user_present_at_hook.lock().unwrap().get(&pid).is_some());
    assert!(unregister_user_erase_hook(NAME));
    assert!(!unregister_user_erase_hook(NAME));
}
