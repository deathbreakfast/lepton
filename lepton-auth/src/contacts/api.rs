//! Contact CRUD and primary selection.

use chrono::Utc;
use lepton_host_adapter::generated::{
    Account, AccountEmail, AccountMembership, AccountPhone, User,
};
use valence::{Model, RecordId, RecordPredicate, StringPredicate, Valence};

use super::ContactError;

fn bare_id(record: &RecordId) -> String {
    valence::extract_id_from_record(record).unwrap_or_else(|_| record.id().to_string())
}

/// Resolve the account for `user` via the first membership (legal-identity account).
pub async fn account_for_user(
    valence: &Valence,
    user: &RecordId,
) -> Result<RecordId, ContactError> {
    let memberships = AccountMembership::query_used(valence, valence::use_!("query AccountMembership in src/contacts/api.rs; Valence persistence for this feature path; typed store; visible to session actor / service path."))
        .where_user(RecordPredicate::Equals(user.clone()))
        .await
        .map_err(|_| ContactError::Store)?;
    memberships
        .into_iter()
        .next()
        .map(|m| m.account().clone())
        .ok_or(ContactError::NotMember)
}

async fn user_is_account_member(
    valence: &Valence,
    account: &RecordId,
    user: &RecordId,
) -> Result<bool, ContactError> {
    let memberships = AccountMembership::query_used(valence, valence::use_!("query AccountMembership in src/contacts/api.rs; Valence persistence for this feature path; typed store; visible to session actor / service path."))
        .where_account(RecordPredicate::Equals(account.clone()))
        .await
        .map_err(|_| ContactError::Store)?;
    let user_bare = bare_id(user);
    Ok(memberships.iter().any(|m| bare_id(m.user()) == user_bare))
}

/// Look up an [`AccountEmail`] by unique address.
///
/// # Errors
///
/// Returns [`ContactError::Store`] on query failure.
pub async fn find_account_email_by_address(
    valence: &Valence,
    address: &str,
) -> Result<Option<AccountEmail>, ContactError> {
    AccountEmail::query_used(valence, valence::use_!("query AccountEmail in src/contacts/api.rs; Valence persistence for this feature path; typed store; visible to session actor / service path."))
        .where_address(StringPredicate::Equals(address.trim().to_string()))
        .first()
        .await
        .map_err(|_| ContactError::Store)
}

/// Create an unverified email contact on `account`.
///
/// # Errors
///
/// [`ContactError::Conflict`] when address is taken; [`ContactError::AccountMissing`] /
/// [`ContactError::Store`] on validation or persistence failure.
pub async fn add_account_email(
    valence: &Valence,
    account: &RecordId,
    address: &str,
) -> Result<AccountEmail, ContactError> {
    let address = address.trim().to_string();
    if find_account_email_by_address(valence, &address)
        .await?
        .is_some()
    {
        #[cfg(feature = "spectra")]
        crate::spectra_emit::contact(
            crate::spectra_emit::VerifyChannel::Email,
            crate::spectra_emit::ContactOperation::Add,
            crate::spectra_emit::AuthOutcome::Failure,
            "address_taken",
        );
        return Err(ContactError::Conflict);
    }
    let account_bare = bare_id(account);
    if Account::get_used(&account_bare, valence, valence::use_!("get Account in src/contacts/api.rs; Valence persistence for this feature path; typed store; visible to session actor / service path."))
        .await
        .map_err(|_| ContactError::Store)?
        .is_none()
    {
        return Err(ContactError::AccountMissing);
    }
    let now = Utc::now();
    let row = AccountEmail::new(account.clone(), address, None, now, now)
        .map_err(|_| ContactError::Store)?;
    let result = AccountEmail::create_used(row, valence, valence::use_!("create AccountEmail in src/contacts/api.rs; Valence persistence for this feature path; typed store; visible to session actor / service path."))
        .await
        .map_err(|_| ContactError::Store);
    #[cfg(feature = "spectra")]
    match &result {
        Ok(_) => crate::spectra_emit::contact(
            crate::spectra_emit::VerifyChannel::Email,
            crate::spectra_emit::ContactOperation::Add,
            crate::spectra_emit::AuthOutcome::Success,
            "none",
        ),
        Err(e) => crate::spectra_emit::contact(
            crate::spectra_emit::VerifyChannel::Email,
            crate::spectra_emit::ContactOperation::Add,
            crate::spectra_emit::AuthOutcome::Failure,
            e.reason_class(),
        ),
    }
    result
}

/// Create an unverified phone contact on `account`.
///
/// # Errors
///
/// [`ContactError::Conflict`] when e164 is taken; [`ContactError::AccountMissing`] /
/// [`ContactError::Store`] on validation or persistence failure.
pub async fn add_account_phone(
    valence: &Valence,
    account: &RecordId,
    e164: &str,
) -> Result<AccountPhone, ContactError> {
    let e164 = e164.trim().to_string();
    let existing = AccountPhone::query_used(valence, valence::use_!("query AccountPhone in src/contacts/api.rs; Valence persistence for this feature path; typed store; visible to session actor / service path."))
        .where_e164(StringPredicate::Equals(e164.clone()))
        .first()
        .await
        .map_err(|_| ContactError::Store)?;
    if existing.is_some() {
        #[cfg(feature = "spectra")]
        crate::spectra_emit::contact(
            crate::spectra_emit::VerifyChannel::Phone,
            crate::spectra_emit::ContactOperation::Add,
            crate::spectra_emit::AuthOutcome::Failure,
            "address_taken",
        );
        return Err(ContactError::Conflict);
    }
    let account_bare = bare_id(account);
    if Account::get_used(&account_bare, valence, valence::use_!("get Account in src/contacts/api.rs; Valence persistence for this feature path; typed store; visible to session actor / service path."))
        .await
        .map_err(|_| ContactError::Store)?
        .is_none()
    {
        return Err(ContactError::AccountMissing);
    }
    let now = Utc::now();
    let row = AccountPhone::new(account.clone(), e164, None, now, now)
        .map_err(|_| ContactError::Store)?;
    let result = AccountPhone::create_used(row, valence, valence::use_!("create AccountPhone in src/contacts/api.rs; Valence persistence for this feature path; typed store; visible to session actor / service path."))
        .await
        .map_err(|_| ContactError::Store);
    #[cfg(feature = "spectra")]
    match &result {
        Ok(_) => crate::spectra_emit::contact(
            crate::spectra_emit::VerifyChannel::Phone,
            crate::spectra_emit::ContactOperation::Add,
            crate::spectra_emit::AuthOutcome::Success,
            "none",
        ),
        Err(e) => crate::spectra_emit::contact(
            crate::spectra_emit::VerifyChannel::Phone,
            crate::spectra_emit::ContactOperation::Add,
            crate::spectra_emit::AuthOutcome::Failure,
            e.reason_class(),
        ),
    }
    result
}

/// Set `user.primary_email` (login FK) to a verified account email the user can access.
pub async fn set_primary_email(
    valence: &Valence,
    user: &RecordId,
    account_email: &RecordId,
) -> Result<(), ContactError> {
    let email_bare = bare_id(account_email);
    let email = AccountEmail::get_used(&email_bare, valence, valence::use_!("get AccountEmail in src/contacts/api.rs; Valence persistence for this feature path; typed store; visible to session actor / service path."))
        .await
        .map_err(|_| ContactError::Store)?
        .ok_or(ContactError::ContactMissing)?;
    if !user_is_account_member(valence, email.account(), user).await? {
        return Err(ContactError::ContactMissing);
    }
    if email.verified_at().is_none() {
        return Err(ContactError::Unverified);
    }
    let uid = bare_id(user);
    let user_row = User::get_used(&uid, valence, valence::use_!("get User in src/contacts/api.rs; Valence persistence for this feature path; typed store; visible to session actor / service path."))
        .await
        .map_err(|_| ContactError::Store)?
        .ok_or(ContactError::UserMissing)?;
    user_row
        .get_mutable_used(valence, valence::use_!("get_mutable via api.rs; mutable handle for in-place update; typed store; session/service path."))
        .set_primary_email(account_email.clone())
        .map_err(|_| ContactError::Store)?
        .set_updated_at(Utc::now())
        .map_err(|_| ContactError::Store)?
        .commit()
        .await
        .map_err(|_| ContactError::Store)?;
    #[cfg(feature = "spectra")]
    crate::spectra_emit::contact(
        crate::spectra_emit::VerifyChannel::Email,
        crate::spectra_emit::ContactOperation::SetPrimary,
        crate::spectra_emit::AuthOutcome::Success,
        "none",
    );
    Ok(())
}

/// Set `account.primary_email` to a verified email that belongs to the account.
pub async fn set_account_primary_email(
    valence: &Valence,
    account: &RecordId,
    account_email: &RecordId,
) -> Result<(), ContactError> {
    let email_bare = bare_id(account_email);
    let email = AccountEmail::get_used(&email_bare, valence, valence::use_!("get AccountEmail in src/contacts/api.rs; Valence persistence for this feature path; typed store; visible to session actor / service path."))
        .await
        .map_err(|_| ContactError::Store)?
        .ok_or(ContactError::ContactMissing)?;
    if email.verified_at().is_none() {
        return Err(ContactError::Unverified);
    }

    let account_bare = bare_id(account);
    let account_row = Account::get_used(&account_bare, valence, valence::use_!("get Account in src/contacts/api.rs; Valence persistence for this feature path; typed store; visible to session actor / service path."))
        .await
        .map_err(|_| ContactError::Store)?
        .ok_or(ContactError::AccountMissing)?;

    if bare_id(email.account()) != account_bare {
        return Err(ContactError::NotMember);
    }

    account_row
        .get_mutable_used(valence, valence::use_!("get_mutable via api.rs; mutable handle for in-place update; typed store; session/service path."))
        .set_primary_email(account_email.clone())
        .map_err(|_| ContactError::Store)?
        .set_updated_at(Utc::now())
        .map_err(|_| ContactError::Store)?
        .commit()
        .await
        .map_err(|_| ContactError::Store)?;
    Ok(())
}

/// Set `user.primary_phone` (login FK) to a verified account phone the user can access.
pub async fn set_primary_phone(
    valence: &Valence,
    user: &RecordId,
    account_phone: &RecordId,
) -> Result<(), ContactError> {
    let phone_bare = bare_id(account_phone);
    let phone = AccountPhone::get_used(&phone_bare, valence, valence::use_!("get AccountPhone in src/contacts/api.rs; Valence persistence for this feature path; typed store; visible to session actor / service path."))
        .await
        .map_err(|_| ContactError::Store)?
        .ok_or(ContactError::ContactMissing)?;
    if !user_is_account_member(valence, phone.account(), user).await? {
        return Err(ContactError::ContactMissing);
    }
    if phone.verified_at().is_none() {
        return Err(ContactError::Unverified);
    }
    let uid = bare_id(user);
    let user_row = User::get_used(&uid, valence, valence::use_!("get User in src/contacts/api.rs; Valence persistence for this feature path; typed store; visible to session actor / service path."))
        .await
        .map_err(|_| ContactError::Store)?
        .ok_or(ContactError::UserMissing)?;
    user_row
        .get_mutable_used(valence, valence::use_!("get_mutable via api.rs; mutable handle for in-place update; typed store; session/service path."))
        .set_primary_phone(account_phone.clone())
        .map_err(|_| ContactError::Store)?
        .set_updated_at(Utc::now())
        .map_err(|_| ContactError::Store)?
        .commit()
        .await
        .map_err(|_| ContactError::Store)?;
    Ok(())
}

/// Set `account.primary_phone` to a verified phone that belongs to the account.
pub async fn set_account_primary_phone(
    valence: &Valence,
    account: &RecordId,
    account_phone: &RecordId,
) -> Result<(), ContactError> {
    let phone_bare = bare_id(account_phone);
    let phone = AccountPhone::get_used(&phone_bare, valence, valence::use_!("get AccountPhone in src/contacts/api.rs; Valence persistence for this feature path; typed store; visible to session actor / service path."))
        .await
        .map_err(|_| ContactError::Store)?
        .ok_or(ContactError::ContactMissing)?;
    if phone.verified_at().is_none() {
        return Err(ContactError::Unverified);
    }

    let account_bare = bare_id(account);
    let account_row = Account::get_used(&account_bare, valence, valence::use_!("get Account in src/contacts/api.rs; Valence persistence for this feature path; typed store; visible to session actor / service path."))
        .await
        .map_err(|_| ContactError::Store)?
        .ok_or(ContactError::AccountMissing)?;

    if bare_id(phone.account()) != account_bare {
        return Err(ContactError::NotMember);
    }

    account_row
        .get_mutable_used(valence, valence::use_!("get_mutable via api.rs; mutable handle for in-place update; typed store; session/service path."))
        .set_primary_phone(account_phone.clone())
        .map_err(|_| ContactError::Store)?
        .set_updated_at(Utc::now())
        .map_err(|_| ContactError::Store)?
        .commit()
        .await
        .map_err(|_| ContactError::Store)?;
    Ok(())
}

/// Mark an [`AccountEmail`] verified and, for members with no login email, set it.
pub async fn mark_account_email_verified(
    valence: &Valence,
    account_email: &AccountEmail,
) -> Result<(), ContactError> {
    let now = Utc::now();
    let email_id = account_email
        .id()
        .cloned()
        .ok_or(ContactError::ContactMissing)?;
    account_email
        .get_mutable_used(valence, valence::use_!("get_mutable via api.rs; mutable handle for in-place update; typed store; session/service path."))
        .set_verified_at(now)
        .map_err(|_| ContactError::Store)?
        .set_updated_at(now)
        .map_err(|_| ContactError::Store)?
        .commit()
        .await
        .map_err(|_| ContactError::Store)?;

    let memberships = AccountMembership::query_used(valence, valence::use_!("query AccountMembership in src/contacts/api.rs; Valence persistence for this feature path; typed store; visible to session actor / service path."))
        .where_account(RecordPredicate::Equals(account_email.account().clone()))
        .await
        .map_err(|_| ContactError::Store)?;
    for membership in memberships {
        let uid = bare_id(membership.user());
        let Some(user) = User::get_used(&uid, valence, valence::use_!("get User in src/contacts/api.rs; Valence persistence for this feature path; typed store; visible to session actor / service path."))
            .await
            .map_err(|_| ContactError::Store)?
        else {
            continue;
        };
        if user.primary_email().is_none() {
            set_primary_email(valence, membership.user(), &email_id).await?;
        }
    }
    #[cfg(feature = "spectra")]
    crate::spectra_emit::contact(
        crate::spectra_emit::VerifyChannel::Email,
        crate::spectra_emit::ContactOperation::MarkVerified,
        crate::spectra_emit::AuthOutcome::Success,
        "none",
    );
    Ok(())
}

/// Mark an [`AccountPhone`] verified and, for members with no login phone, set it.
pub async fn mark_account_phone_verified(
    valence: &Valence,
    account_phone: &AccountPhone,
) -> Result<(), ContactError> {
    let now = Utc::now();
    let phone_id = account_phone
        .id()
        .cloned()
        .ok_or(ContactError::ContactMissing)?;
    account_phone
        .get_mutable_used(valence, valence::use_!("get_mutable via api.rs; mutable handle for in-place update; typed store; session/service path."))
        .set_verified_at(now)
        .map_err(|_| ContactError::Store)?
        .set_updated_at(now)
        .map_err(|_| ContactError::Store)?
        .commit()
        .await
        .map_err(|_| ContactError::Store)?;

    let memberships = AccountMembership::query_used(valence, valence::use_!("query AccountMembership in src/contacts/api.rs; Valence persistence for this feature path; typed store; visible to session actor / service path."))
        .where_account(RecordPredicate::Equals(account_phone.account().clone()))
        .await
        .map_err(|_| ContactError::Store)?;
    for membership in memberships {
        let uid = bare_id(membership.user());
        let Some(user) = User::get_used(&uid, valence, valence::use_!("get User in src/contacts/api.rs; Valence persistence for this feature path; typed store; visible to session actor / service path."))
            .await
            .map_err(|_| ContactError::Store)?
        else {
            continue;
        };
        if user.primary_phone().is_none() {
            set_primary_phone(valence, membership.user(), &phone_id).await?;
        }
    }
    Ok(())
}
