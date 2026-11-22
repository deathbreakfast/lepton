//! `erase_account` applies each deletion-graph node's action, and runs product hooks first.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Once};

use lepton_auth::identity_delete::{
    erase_account, register_erase_account_hook, EraseAccountHook, IdentityDeleteError,
};
use lepton_auth::service_users::{list_service_user_activity, suspend_service_user};
use lepton_host_adapter::generated::{Account, ServiceUserActivityKind as Kind, User};
use valence::{Model, RecordId, Valence};

use crate::service_users_owner_delete::seed_account_with_members;
use crate::service_users_support::{install_test_gate, seed_service_user, seed_user};
use crate::support::{system_valence, user_valence};

const HOOK_SEEN_USER: &str = "erase-hook-seen";
const HOOK_FAIL_USER: &str = "erase-hook-fail";

/// Set when the observing hook ran while the user row still existed.
static SAW_USER_ROW: AtomicBool = AtomicBool::new(false);

/// Hooks are process-wide, so each one only acts on its own test user.
struct ObserveHook;

#[async_trait::async_trait]
impl EraseAccountHook for ObserveHook {
    fn name(&self) -> &'static str {
        "test.observe"
    }

    async fn before_user_erase(
        &self,
        valence: &Valence,
        user: &RecordId,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if user.id() != HOOK_SEEN_USER {
            return Ok(());
        }
        let row = User::get(HOOK_SEEN_USER, valence, valence::use_!(r"**Test:** Fixture read of a **User** inside an erase hook so the suite can check the row still exists when hooks run. CI and developers running the suite only."))
            .await?;
        SAW_USER_ROW.store(row.is_some(), Ordering::SeqCst);
        Ok(())
    }
}

struct FailHook;

#[async_trait::async_trait]
impl EraseAccountHook for FailHook {
    fn name(&self) -> &'static str {
        "test.fail"
    }

    async fn before_user_erase(
        &self,
        _valence: &Valence,
        user: &RecordId,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if user.id() == HOOK_FAIL_USER {
            return Err("scrub failed".into());
        }
        Ok(())
    }
}

fn setup() {
    install_test_gate();
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
    static HOOKS: Once = Once::new();
    HOOKS.call_once(|| {
        register_erase_account_hook(Arc::new(ObserveHook));
        register_erase_account_hook(Arc::new(FailHook));
    });
}

/// A row that only references the erased user (`SetNull`) survives with the field cleared.
#[tokio::test]
async fn erase_account_set_nulls_actor_and_keeps_row_happy() {
    setup();
    let sys = system_valence("erase_account_set_null").await;
    let (owner, id, _) = seed_service_user(&sys, "maker-erase-setnull", "setnull-bot").await;
    seed_user(&sys, "super-erase-setnull").await;
    let admin = user_valence(&sys, "super-erase-setnull");
    suspend_service_user(&admin, &id)
        .await
        .expect("admin suspends");
    let account = seed_account_with_members(&sys, "erase-setnull", &["super-erase-setnull"]).await;

    erase_account(&sys, &account).await.expect("erase admin");

    let rows = list_service_user_activity(&owner, &id, None)
        .await
        .expect("list");
    let suspended = rows
        .iter()
        .find(|r| *r.kind() == Kind::Suspended)
        .expect("the admin's activity row survives");
    assert!(suspended.actor().is_none(), "actor is cleared");
    assert!(
        rows.iter()
            .any(|r| r.actor().map(RecordId::id) == Some("maker-erase-setnull")),
        "the owner's own rows keep their actor"
    );
}

#[tokio::test]
async fn erase_account_runs_hooks_before_deleting_happy() {
    setup();
    let sys = system_valence("erase_account_hook_seen").await;
    seed_user(&sys, HOOK_SEEN_USER).await;
    let account = seed_account_with_members(&sys, "erase-hook-seen", &[HOOK_SEEN_USER]).await;

    erase_account(&sys, &account).await.expect("erase");

    assert!(
        SAW_USER_ROW.load(Ordering::SeqCst),
        "the hook ran while the user row still existed"
    );
    let user = User::get(HOOK_SEEN_USER, &sys, valence::use_!(r"**Test:** Fixture read of a **User** after erase so the suite can check the row is gone. CI and developers running the suite only."))
        .await
        .expect("read");
    assert!(user.is_none(), "the user is erased after the hook");
}

#[tokio::test]
async fn erase_account_hook_failure_deletes_nothing_sad() {
    setup();
    let sys = system_valence("erase_account_hook_fail").await;
    seed_user(&sys, HOOK_FAIL_USER).await;
    let account = seed_account_with_members(&sys, "erase-hook-fail", &[HOOK_FAIL_USER]).await;

    let err = erase_account(&sys, &account)
        .await
        .expect_err("the failing hook stops the erase");

    assert!(matches!(err, IdentityDeleteError::Hook));
    assert_eq!(err.reason_class(), "hook");
    let still = Account::get(account.id(), &sys, valence::use_!(r"**Test:** Fixture read of an **Account** after a failed erase so the suite can check nothing was deleted. CI and developers running the suite only."))
        .await
        .expect("read");
    assert!(still.is_some(), "the account is still there");
}
