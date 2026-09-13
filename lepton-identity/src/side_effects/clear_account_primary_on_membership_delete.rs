//! Clear Account primary email/phone when a departing member's login matched.

use async_trait::async_trait;
use valence::{
    extract_id_from_record, Model, Mutation, MutationKind, RecordId, SideEffect, Valence,
};

use crate::generated::{Account, AccountMembership, User};

#[cfg(feature = "test-utils")]
mod fault_inject {
    use std::sync::atomic::{AtomicBool, Ordering};

    static FORCE_CLEAR_FAIL: AtomicBool = AtomicBool::new(false);

    /// When true, [`super::clear_account_primaries_if_login_matched`] returns an error
    /// so callers can assert Valence's log-only SideEffect contract.
    pub fn force_primary_clear_failure(force: bool) {
        FORCE_CLEAR_FAIL.store(force, Ordering::SeqCst);
    }

    pub(super) fn should_fail() -> bool {
        FORCE_CLEAR_FAIL.load(Ordering::SeqCst)
    }
}

#[cfg(feature = "test-utils")]
pub use fault_inject::force_primary_clear_failure;

/// Clear Account primary email/phone when the departing user's login FKs matched.
///
/// Used by the membership delete `SideEffect` and by in-process membership deletes that
/// skip `Model::delete` / Chronon.
///
/// Failures should be treated as log-only by callers (Valence SE contract).
pub async fn clear_account_primaries_if_login_matched(
    valence: &Valence,
    account: &RecordId,
    user: &RecordId,
) -> valence::Result<()> {
    #[cfg(feature = "test-utils")]
    if fault_inject::should_fail() {
        return Err(valence::Error::Internal(
            "forced account primary clear failure (test-utils)".into(),
        ));
    }

    let account_bare = extract_id_from_record(account).unwrap_or_default();
    let user_bare = extract_id_from_record(user).unwrap_or_default();

    let Some(account_row) = Account::get_used(&account_bare, valence, valence::use_!("get Account in src/side_effects/clear_account_primary_on_membership_delete.rs; Valence persistence for this feature path; typed store; visible to session actor / service path.")).await? else {
        return Ok(());
    };
    let Some(user_row) = User::get_used(&user_bare, valence, valence::use_!("get User in src/side_effects/clear_account_primary_on_membership_delete.rs; Valence persistence for this feature path; typed store; visible to session actor / service path.")).await? else {
        return Ok(());
    };

    let mut mutable = account_row.get_mutable_used(valence, valence::use_!("get_mutable via clear_account_primary_on_membership_delete.rs; mutable handle for in-place update; typed store; session/service path."));
    let mut changed = false;

    if let (Some(acct_primary), Some(login)) =
        (account_row.primary_email(), user_row.primary_email())
    {
        let a = extract_id_from_record(acct_primary).unwrap_or_default();
        let u = extract_id_from_record(login).unwrap_or_default();
        if a == u && !a.is_empty() {
            mutable = mutable.clear_primary_email();
            changed = true;
            tracing::info!(
                reason_class = "account_primary_cleared_on_membership_delete",
                contact_kind = "email",
                "cleared account primary email after membership delete"
            );
        }
    }

    if let (Some(acct_primary), Some(login)) =
        (account_row.primary_phone(), user_row.primary_phone())
    {
        let a = extract_id_from_record(acct_primary).unwrap_or_default();
        let u = extract_id_from_record(login).unwrap_or_default();
        if a == u && !a.is_empty() {
            mutable = mutable.clear_primary_phone();
            changed = true;
            tracing::info!(
                reason_class = "account_primary_cleared_on_membership_delete",
                contact_kind = "phone",
                "cleared account primary phone after membership delete"
            );
        }
    }

    if changed {
        mutable.commit().await?;
    }
    Ok(())
}

/// On membership delete: if the departing user's login email/phone is the Account
/// primary, clear that Account primary (log-only on failure per Valence SE contract).
pub struct ClearAccountPrimaryOnMembershipDelete;

#[async_trait]
impl SideEffect<AccountMembership> for ClearAccountPrimaryOnMembershipDelete {
    async fn on_mutation(&self, mutation: &Mutation<'_, AccountMembership>) -> valence::Result<()> {
        if !matches!(mutation.kind(), MutationKind::Delete) {
            return Ok(());
        }
        let Some(before) = mutation.before() else {
            return Ok(());
        };
        clear_account_primaries_if_login_matched(
            mutation.valence(),
            before.account(),
            before.user(),
        )
        .await
    }
}
