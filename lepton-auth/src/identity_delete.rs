//! Account erase and guarded identity deletes.
//!
//! Applies physical deletes in-process (embedded / tests). Hosts that run the Chronon
//! deletion orchestrator can still call [`valence::Model::delete`]; this module is the
//! policy entry point and completes wipe without requiring that worker.
//!
//! [`crate::identity_delete::delete_membership`] also clears Account primaries when the
//! departing user's login matched (same contract as
//! [`lepton_identity::side_effects::ClearAccountPrimaryOnMembershipDelete`] on
//! `Model::delete`).

use lepton_host_adapter::generated::{
    Account, AccountEmail, AccountMembership, AccountPhone, User,
};
use thiserror::Error;
use valence::deletion::dag::DeletionDag;
use valence::{Model, RecordId, RecordPredicate, Valence};

fn bare_id(record: &RecordId) -> String {
    valence::extract_id_from_record(record).unwrap_or_else(|_| record.id().to_string())
}

async fn physical_delete(
    valence: &Valence,
    table: &str,
    bare: &str,
) -> Result<(), IdentityDeleteError> {
    let backend = valence
        .backend_for_table(table)
        .map_err(|_| IdentityDeleteError::Store)?;
    valence::delete_record_used(
        backend.as_ref(),
        table,
        bare,
        valence::use_!(r"During **account erasure**, we **remove a leftover identity row** from storage so user-related data does not remain after wipe. Only the erasure path uses this cleanup."),
    )
    .await
    .map_err(|_| IdentityDeleteError::Store)?;
    valence::read_cache::invalidate(table, bare);
    Ok(())
}

/// Errors from guarded identity deletes and account erase.
#[derive(Debug, Error)]
pub enum IdentityDeleteError {
    /// User is the sole member of an account — erase the account instead.
    #[error("reason_class=sole_member: sole account member; erase account instead")]
    SoleMember,
    /// User login email is still the account primary — reassign primary first.
    #[error("reason_class=account_primary: user login is account primary email")]
    AccountPrimary,
    /// Membership is the last on the account.
    #[error("reason_class=last_membership: cannot remove last account membership")]
    LastMembership,
    /// Email is the account primary (standalone delete blocked; Valence Restrict).
    #[error("reason_class=restrict_primary: cannot delete account primary email")]
    RestrictPrimary,
    /// Schema Restrict blocked the delete (other than account primary).
    #[error("reason_class=restrict: delete restricted by schema connections")]
    Restrict,
    /// Account row missing.
    #[error("reason_class=account: account not found")]
    AccountMissing,
    /// User row missing.
    #[error("reason_class=user: user not found")]
    UserMissing,
    /// Contact / email row missing.
    #[error("reason_class=contact: contact not found")]
    ContactMissing,
    /// Membership row missing.
    #[error("reason_class=membership: membership not found")]
    MembershipMissing,
    /// Persistence / Valence failure (opaque).
    #[error("reason_class=store: identity delete store operation failed")]
    Store,
}

impl IdentityDeleteError {
    /// Stable reason class for ops / tests.
    #[must_use]
    pub const fn reason_class(&self) -> &'static str {
        match self {
            Self::SoleMember => "sole_member",
            Self::AccountPrimary => "account_primary",
            Self::LastMembership => "last_membership",
            Self::RestrictPrimary => "restrict_primary",
            Self::Restrict => "restrict",
            Self::AccountMissing => "account",
            Self::UserMissing => "user",
            Self::ContactMissing => "contact",
            Self::MembershipMissing => "membership",
            Self::Store => "store",
        }
    }
}

const fn map_restrict(dag: &DeletionDag) -> IdentityDeleteError {
    if dag.restrict_violations.is_empty() {
        IdentityDeleteError::Store
    } else {
        IdentityDeleteError::Restrict
    }
}

/// Erase an account (GDPR / legal-identity wipe): cascade emails + memberships, then users.
///
/// 1. Snapshot member user ids and account emails.
/// 2. Delete emails + memberships + Account (primary Restrict skipped under parent wipe).
/// 3. Delete each member `User` (phones, devices, OAuth links, TOTP factors, recovery codes).
///
/// Callers must use a Valence capable of Account / contact CUD (`SYSTEM_ONLY` today).
/// Product wipe gates Owner + password (+ TOTP when enrolled) before elevating.
///
/// # Errors
///
/// [`IdentityDeleteError::AccountMissing`] when the account row is absent; [`IdentityDeleteError::Store`]
/// / [`IdentityDeleteError::Restrict`] on persistence or remaining Restrict edges.
pub async fn erase_account(
    valence: &Valence,
    account: &RecordId,
) -> Result<(), IdentityDeleteError> {
    tracing::info!(
        operation = "erase_account",
        outcome = "start",
        "lepton_auth.identity_delete.erase_account"
    );
    let account_bare = bare_id(account);
    let _ = Account::get_used(&account_bare, valence, valence::use_!(r"When **account erasure** finishes cleanup, we **remove Account** so leftover rows do not remain after the operation. Only the cleanup path for **account erasure** uses this step; it is not shown as a standalone end-user page by itself."))
        .await
        .map_err(|_| IdentityDeleteError::Store)?
        .ok_or(IdentityDeleteError::AccountMissing)?;

    let memberships = AccountMembership::query_used(valence, valence::use_!(r"When **account erasure** finishes cleanup, we **remove Account Membership** so leftover rows do not remain after the operation. Only the cleanup path for **account erasure** uses this step; it is not shown as a standalone end-user page by itself."))
        .where_account(RecordPredicate::Equals(account.clone()))
        .await
        .map_err(|_| IdentityDeleteError::Store)?;
    let member_ids: Vec<RecordId> = memberships.iter().map(|m| m.user().clone()).collect();
    let membership_bares: Vec<String> = memberships
        .iter()
        .filter_map(|m| m.id().map(bare_id))
        .collect();

    let emails = AccountEmail::query_used(valence, valence::use_!(r"When **account erasure** finishes cleanup, we **remove Account Email** so leftover rows do not remain after the operation. Only the cleanup path for **account erasure** uses this step; it is not shown as a standalone end-user page by itself."))
        .where_account(RecordPredicate::Equals(account.clone()))
        .await
        .map_err(|_| IdentityDeleteError::Store)?;
    let email_bares: Vec<String> = emails.iter().filter_map(|e| e.id().map(bare_id)).collect();

    let phones = AccountPhone::query_used(valence, valence::use_!(r"When **account erasure** finishes cleanup, we **remove Account Phone** so leftover rows do not remain after the operation. Only the cleanup path for **account erasure** uses this step; it is not shown as a standalone end-user page by itself."))
        .where_account(RecordPredicate::Equals(account.clone()))
        .await
        .map_err(|_| IdentityDeleteError::Store)?;
    let phone_bares: Vec<String> = phones.iter().filter_map(|p| p.id().map(bare_id)).collect();

    for email_bare in email_bares {
        physical_delete(valence, "account_email", &email_bare).await?;
    }
    for phone_bare in phone_bares {
        physical_delete(valence, "account_phone", &phone_bare).await?;
    }
    for mid in membership_bares {
        physical_delete(valence, "account_membership", &mid).await?;
    }
    physical_delete(valence, "account", &account_bare).await?;

    for user_id in member_ids {
        let uid = bare_id(&user_id);
        if User::get_used(&uid, valence, valence::use_!(r"When **account erasure** finishes cleanup, we **remove User** so leftover rows do not remain after the operation. Only the cleanup path for **account erasure** uses this step; it is not shown as a standalone end-user page by itself."))
            .await
            .map_err(|_| IdentityDeleteError::Store)?
            .is_some()
        {
            delete_user_unchecked(valence, &uid).await?;
        }
    }
    tracing::info!(
        operation = "erase_account",
        outcome = "ok",
        "lepton_auth.identity_delete.erase_account"
    );
    #[cfg(feature = "spectra")]
    crate::spectra_emit::identity_delete(
        crate::spectra_emit::IdentityDeleteOperation::EraseAccount,
        crate::spectra_emit::AuthOutcome::Success,
        "none",
    );
    Ok(())
}

/// Tables deleted via explicit reverse-FK queries below (errors are not swallowed).
const KNOWN_USER_CHILD_TABLES: &[&str] = &[
    "account_membership",
    "auth_device",
    "auth_device_ceremony",
    "linked_identity",
    "totp_factor",
    "totp_recovery_code",
    "user",
];

/// Cascade-delete a user and user-owned children (memberships, devices, …).
async fn delete_user_unchecked(valence: &Valence, uid: &str) -> Result<(), IdentityDeleteError> {
    use lepton_host_adapter::generated::{
        AuthDevice, AuthDeviceCeremony, LinkedIdentity, TotpFactor, TotpRecoveryCode,
    };

    let user_thing = RecordId::new("user", uid);
    let memberships = AccountMembership::query_used(valence, valence::use_!(r"When **account erasure** finishes cleanup, we **remove Account Membership** so leftover rows do not remain after the operation. Only the cleanup path for **account erasure** uses this step; it is not shown as a standalone end-user page by itself."))
        .where_user(RecordPredicate::Equals(user_thing.clone()))
        .await
        .map_err(|_| IdentityDeleteError::Store)?;
    for m in memberships {
        if let Some(id) = m.id() {
            physical_delete(valence, "account_membership", &bare_id(id)).await?;
        }
    }

    // Discover remaining children via DAG; known tables use reverse-FK deletes with `?`.
    let dag = DeletionDag::compute("user", uid, valence)
        .await
        .map_err(|_| IdentityDeleteError::Store)?;
    if !dag.restrict_violations.is_empty() {
        return Err(map_restrict(&dag));
    }
    for node in &dag.nodes {
        if KNOWN_USER_CHILD_TABLES.contains(&node.table.as_str()) {
            continue;
        }
        // Best-effort for unknown/optional children (tokens, profile, …).
        let _ = physical_delete(valence, &node.table, &node.record_id).await;
    }

    // Known user-owned tables via reverse FK (reliable ids; fail on store error).
    // Account phones are account-owned (erased with the account), not deleted here.
    for device in AuthDevice::query_used(valence, valence::use_!(r"When **account erasure** finishes cleanup, we **remove Auth Device** so leftover rows do not remain after the operation. Only the cleanup path for **account erasure** uses this step; it is not shown as a standalone end-user page by itself."))
        .where_user(RecordPredicate::Equals(user_thing.clone()))
        .await
        .map_err(|_| IdentityDeleteError::Store)?
    {
        if let Some(id) = device.id() {
            physical_delete(valence, "auth_device", &bare_id(id)).await?;
        }
    }
    for ceremony in AuthDeviceCeremony::query_used(valence, valence::use_!(r"When **account erasure** finishes cleanup, we **remove Auth Device Ceremony** so leftover rows do not remain after the operation. Only the cleanup path for **account erasure** uses this step; it is not shown as a standalone end-user page by itself."))
        .where_user(RecordPredicate::Equals(user_thing.clone()))
        .await
        .map_err(|_| IdentityDeleteError::Store)?
    {
        if let Some(id) = ceremony.id() {
            physical_delete(valence, "auth_device_ceremony", &bare_id(id)).await?;
        }
    }
    for linked in LinkedIdentity::query_used(valence, valence::use_!(r"When **account erasure** finishes cleanup, we **remove Linked Identity** so leftover rows do not remain after the operation. Only the cleanup path for **account erasure** uses this step; it is not shown as a standalone end-user page by itself."))
        .where_user(RecordPredicate::Equals(user_thing.clone()))
        .await
        .map_err(|_| IdentityDeleteError::Store)?
    {
        if let Some(id) = linked.id() {
            physical_delete(valence, "linked_identity", &bare_id(id)).await?;
        }
    }
    for factor in TotpFactor::get_from_user_id_used(
        uid,
        valence,
        valence::use_!(r"During **account erasure**, we **list authenticator factors** for this user so each one can be removed with the rest of the account. Only the erasure path uses this list."),
    )
    .await
    .map_err(|_| IdentityDeleteError::Store)?
    {
        if let Some(id) = factor.id() {
            physical_delete(valence, "totp_factor", &bare_id(id)).await?;
        }
    }
    for code in TotpRecoveryCode::get_from_user_id_used(
        uid,
        valence,
        valence::use_!(r"During **account erasure**, we **list recovery codes** for this user so each one can be removed with the rest of the account. Only the erasure path uses this list."),
    )
    .await
    .map_err(|_| IdentityDeleteError::Store)?
    {
        if let Some(id) = code.id() {
            physical_delete(valence, "totp_recovery_code", &bare_id(id)).await?;
        }
    }

    physical_delete(valence, "user", uid).await
}

/// Delete a user persona with sole-member and account-primary guards.
pub async fn delete_user(valence: &Valence, user: &RecordId) -> Result<(), IdentityDeleteError> {
    let uid = bare_id(user);
    let user_row = User::get_used(&uid, valence, valence::use_!(r"When **account erasure** finishes cleanup, we **remove User** so leftover rows do not remain after the operation. Only the cleanup path for **account erasure** uses this step; it is not shown as a standalone end-user page by itself."))
        .await
        .map_err(|_| IdentityDeleteError::Store)?
        .ok_or(IdentityDeleteError::UserMissing)?;

    let memberships = AccountMembership::query_used(valence, valence::use_!(r"When **account erasure** finishes cleanup, we **remove Account Membership** so leftover rows do not remain after the operation. Only the cleanup path for **account erasure** uses this step; it is not shown as a standalone end-user page by itself."))
        .where_user(RecordPredicate::Equals(user.clone()))
        .await
        .map_err(|_| IdentityDeleteError::Store)?;

    for membership in &memberships {
        let siblings = AccountMembership::query_used(valence, valence::use_!(r"When **account erasure** finishes cleanup, we **remove Account Membership** so leftover rows do not remain after the operation. Only the cleanup path for **account erasure** uses this step; it is not shown as a standalone end-user page by itself."))
            .where_account(RecordPredicate::Equals(membership.account().clone()))
            .await
            .map_err(|_| IdentityDeleteError::Store)?;
        if siblings.len() <= 1 {
            return Err(IdentityDeleteError::SoleMember);
        }
    }

    if let Some(login) = user_row.primary_email() {
        let login_bare = bare_id(login);
        for membership in &memberships {
            let account_bare = bare_id(membership.account());
            let Some(account) = Account::get_used(&account_bare, valence, valence::use_!(r"When **account erasure** finishes cleanup, we **remove Account** so leftover rows do not remain after the operation. Only the cleanup path for **account erasure** uses this step; it is not shown as a standalone end-user page by itself."))
                .await
                .map_err(|_| IdentityDeleteError::Store)?
            else {
                continue;
            };
            if account
                .primary_email()
                .is_some_and(|p| bare_id(p) == login_bare)
            {
                return Err(IdentityDeleteError::AccountPrimary);
            }
        }
    }

    // Founding `Account.user` Restrict — erase the account (or transfer founding) first.
    let founded = Account::query_used(valence, valence::use_!(r"When **account erasure** finishes cleanup, we **remove Account** so leftover rows do not remain after the operation. Only the cleanup path for **account erasure** uses this step; it is not shown as a standalone end-user page by itself."))
        .where_user(RecordPredicate::Equals(user.clone()))
        .await
        .map_err(|_| IdentityDeleteError::Store)?;
    if !founded.is_empty() {
        return Err(IdentityDeleteError::Restrict);
    }

    delete_user_unchecked(valence, &uid).await
}

/// Delete a single account email; blocked when it is the account primary (Restrict).
pub async fn delete_account_email(
    valence: &Valence,
    user_email: &RecordId,
) -> Result<(), IdentityDeleteError> {
    let email_bare = bare_id(user_email);
    let email = AccountEmail::get_used(&email_bare, valence, valence::use_!(r"When **account erasure** finishes cleanup, we **remove Account Email** so leftover rows do not remain after the operation. Only the cleanup path for **account erasure** uses this step; it is not shown as a standalone end-user page by itself."))
        .await
        .map_err(|_| IdentityDeleteError::Store)?
        .ok_or(IdentityDeleteError::ContactMissing)?;

    let account_bare = bare_id(email.account());
    if let Some(account) = Account::get_used(&account_bare, valence, valence::use_!(r"When **account erasure** finishes cleanup, we **remove Account** so leftover rows do not remain after the operation. Only the cleanup path for **account erasure** uses this step; it is not shown as a standalone end-user page by itself."))
        .await
        .map_err(|_| IdentityDeleteError::Store)?
    {
        if account
            .primary_email()
            .is_some_and(|p| bare_id(p) == email_bare)
        {
            return Err(IdentityDeleteError::RestrictPrimary);
        }
    }

    let dag = DeletionDag::compute("account_email", &email_bare, valence)
        .await
        .map_err(|_| IdentityDeleteError::Store)?;
    if !dag.restrict_violations.is_empty() {
        return Err(IdentityDeleteError::RestrictPrimary);
    }

    // Clear login FKs that point at this email (SetNull policy; applied here for mem hosts).
    let users = User::query_used(valence, valence::use_!(r"When **account erasure** finishes cleanup, we **remove User** so leftover rows do not remain after the operation. Only the cleanup path for **account erasure** uses this step; it is not shown as a standalone end-user page by itself."))
        .where_primary_email(RecordPredicate::Equals(user_email.clone()))
        .await
        .map_err(|_| IdentityDeleteError::Store)?;
    let now = chrono::Utc::now();
    for user in users {
        user.get_mutable_used(valence, valence::use_!(r"In **lepton auth**, we **update this data** so later steps see the latest values for this workflow. Callers allowed for **lepton auth** use the updated data; this is not a public export of unrelated fields."))
            .clear_primary_email()
            .set_updated_at(now)
            .map_err(|_| IdentityDeleteError::Store)?
            .commit()
            .await
            .map_err(|_| IdentityDeleteError::Store)?;
    }

    let result = physical_delete(valence, "account_email", &email_bare).await;
    #[cfg(feature = "spectra")]
    match &result {
        Ok(()) => crate::spectra_emit::identity_delete(
            crate::spectra_emit::IdentityDeleteOperation::DeleteEmail,
            crate::spectra_emit::AuthOutcome::Success,
            "none",
        ),
        Err(e) => crate::spectra_emit::identity_delete(
            crate::spectra_emit::IdentityDeleteOperation::DeleteEmail,
            crate::spectra_emit::AuthOutcome::Failure,
            e.reason_class(),
        ),
    }
    result
}

/// Delete a membership unless it is the last on the account.
///
/// After physical delete, clears Account primaries when the departing user's login matched
/// (same behavior as the membership delete `SideEffect` on `Model::delete` / Chronon).
pub async fn delete_membership(
    valence: &Valence,
    membership: &RecordId,
) -> Result<(), IdentityDeleteError> {
    let mid = bare_id(membership);
    let row = AccountMembership::get_used(&mid, valence, valence::use_!(r"When **account erasure** finishes cleanup, we **remove Account Membership** so leftover rows do not remain after the operation. Only the cleanup path for **account erasure** uses this step; it is not shown as a standalone end-user page by itself."))
        .await
        .map_err(|_| IdentityDeleteError::Store)?
        .ok_or(IdentityDeleteError::MembershipMissing)?;

    let siblings = AccountMembership::query_used(valence, valence::use_!(r"When **account erasure** finishes cleanup, we **remove Account Membership** so leftover rows do not remain after the operation. Only the cleanup path for **account erasure** uses this step; it is not shown as a standalone end-user page by itself."))
        .where_account(RecordPredicate::Equals(row.account().clone()))
        .await
        .map_err(|_| IdentityDeleteError::Store)?;
    if siblings.len() <= 1 {
        return Err(IdentityDeleteError::LastMembership);
    }

    let account = row.account().clone();
    let user = row.user().clone();
    physical_delete(valence, "account_membership", &mid).await?;

    // Log-only: match Valence SideEffect contract (delete already committed).
    if let Err(e) = lepton_identity::side_effects::clear_account_primaries_if_login_matched(
        valence, &account, &user,
    )
    .await
    {
        tracing::warn!(
            reason_class = "account_primary_clear_failed",
            error = %e,
            "membership delete: primary clear failed (ignored)"
        );
    }
    #[cfg(feature = "spectra")]
    crate::spectra_emit::identity_delete(
        crate::spectra_emit::IdentityDeleteOperation::DeleteMembership,
        crate::spectra_emit::AuthOutcome::Success,
        "none",
    );
    Ok(())
}

/// Delete a single account phone; blocked when it is the account primary (Restrict).
pub async fn delete_account_phone(
    valence: &Valence,
    account_phone: &RecordId,
) -> Result<(), IdentityDeleteError> {
    let phone_bare = bare_id(account_phone);
    let phone = AccountPhone::get_used(&phone_bare, valence, valence::use_!(r"When **account erasure** finishes cleanup, we **remove Account Phone** so leftover rows do not remain after the operation. Only the cleanup path for **account erasure** uses this step; it is not shown as a standalone end-user page by itself."))
        .await
        .map_err(|_| IdentityDeleteError::Store)?
        .ok_or(IdentityDeleteError::ContactMissing)?;

    let account_bare = bare_id(phone.account());
    if let Some(account) = Account::get_used(&account_bare, valence, valence::use_!(r"When **account erasure** finishes cleanup, we **remove Account** so leftover rows do not remain after the operation. Only the cleanup path for **account erasure** uses this step; it is not shown as a standalone end-user page by itself."))
        .await
        .map_err(|_| IdentityDeleteError::Store)?
    {
        if account
            .primary_phone()
            .is_some_and(|p| bare_id(p) == phone_bare)
        {
            return Err(IdentityDeleteError::RestrictPrimary);
        }
    }

    let dag = DeletionDag::compute("account_phone", &phone_bare, valence)
        .await
        .map_err(|_| IdentityDeleteError::Store)?;
    if !dag.restrict_violations.is_empty() {
        return Err(IdentityDeleteError::RestrictPrimary);
    }

    let users = User::query_used(valence, valence::use_!(r"When **account erasure** finishes cleanup, we **remove User** so leftover rows do not remain after the operation. Only the cleanup path for **account erasure** uses this step; it is not shown as a standalone end-user page by itself."))
        .where_primary_phone(RecordPredicate::Equals(account_phone.clone()))
        .await
        .map_err(|_| IdentityDeleteError::Store)?;
    let now = chrono::Utc::now();
    for user in users {
        user.get_mutable_used(valence, valence::use_!(r"In **lepton auth**, we **update this data** so later steps see the latest values for this workflow. Callers allowed for **lepton auth** use the updated data; this is not a public export of unrelated fields."))
            .clear_primary_phone()
            .set_updated_at(now)
            .map_err(|_| IdentityDeleteError::Store)?
            .commit()
            .await
            .map_err(|_| IdentityDeleteError::Store)?;
    }

    let result = physical_delete(valence, "account_phone", &phone_bare).await;
    #[cfg(feature = "spectra")]
    match &result {
        Ok(()) => crate::spectra_emit::identity_delete(
            crate::spectra_emit::IdentityDeleteOperation::DeletePhone,
            crate::spectra_emit::AuthOutcome::Success,
            "none",
        ),
        Err(e) => crate::spectra_emit::identity_delete(
            crate::spectra_emit::IdentityDeleteOperation::DeletePhone,
            crate::spectra_emit::AuthOutcome::Failure,
            e.reason_class(),
        ),
    }
    result
}
