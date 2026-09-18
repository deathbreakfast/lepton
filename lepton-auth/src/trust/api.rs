//! Confirm / id-verify library APIs.

use chrono::Utc;
use lepton_host_adapter::generated::{AccountEmail, AccountPhone, User};
use valence::{Model, RecordId, Valence};

use super::TrustError;

fn bare_id(record: &RecordId) -> String {
    valence::extract_id_from_record(record).unwrap_or_else(|_| record.id().to_string())
}

async fn load_user(valence: &Valence, user: &RecordId) -> Result<User, TrustError> {
    let uid = bare_id(user);
    User::get_used(&uid, valence, valence::use_!(r"In **trust**, we **load User** so the application can decide what to do next in this workflow. The result is used by **trust** logic—not necessarily displayed on a page unless that feature’s UI shows it."))
        .await
        .map_err(|_| TrustError::Store)?
        .ok_or(TrustError::UserMissing)
}

/// Whether the user's primary email contact has `verified_at`.
///
/// # Errors
///
/// [`TrustError::Store`] / [`TrustError::UserMissing`].
pub async fn primary_email_verified(
    valence: &Valence,
    user: &RecordId,
) -> Result<bool, TrustError> {
    let user = load_user(valence, user).await?;
    let Some(primary) = user.primary_email() else {
        return Ok(false);
    };
    let email = AccountEmail::get_used(&bare_id(primary), valence, valence::use_!(r"In **trust**, we **load Account Email** so the application can decide what to do next in this workflow. The result is used by **trust** logic—not necessarily displayed on a page unless that feature’s UI shows it."))
        .await
        .map_err(|_| TrustError::Store)?;
    Ok(email.is_some_and(|e| e.verified_at().is_some()))
}

/// Whether the user's primary phone contact has `verified_at`.
///
/// # Errors
///
/// [`TrustError::Store`] / [`TrustError::UserMissing`].
pub async fn primary_phone_verified(
    valence: &Valence,
    user: &RecordId,
) -> Result<bool, TrustError> {
    let user = load_user(valence, user).await?;
    let Some(primary) = user.primary_phone() else {
        return Ok(false);
    };
    let phone = AccountPhone::get_used(&bare_id(primary), valence, valence::use_!(r"In **trust**, we **load Account Phone** so the application can decide what to do next in this workflow. The result is used by **trust** logic—not necessarily displayed on a page unless that feature’s UI shows it."))
        .await
        .map_err(|_| TrustError::Store)?;
    Ok(phone.is_some_and(|p| p.verified_at().is_some()))
}

/// Whether `User.confirmed_at` is set.
///
/// # Errors
///
/// Store / missing user.
pub async fn is_confirmed(valence: &Valence, user: &RecordId) -> Result<bool, TrustError> {
    Ok(load_user(valence, user).await?.confirmed_at().is_some())
}

/// Whether `User.id_verified_at` is set.
///
/// # Errors
///
/// Store / missing user.
pub async fn is_id_verified(valence: &Valence, user: &RecordId) -> Result<bool, TrustError> {
    Ok(load_user(valence, user).await?.id_verified_at().is_some())
}

/// Set `confirmed_at` when both primary email and primary phone are verified.
///
/// Login must **not** require this flag (soft gate; product UI may prompt).
///
/// # Errors
///
/// [`TrustError::ConfirmBlocked`] when primaries are missing or unverified.
pub async fn confirm_user(valence: &Valence, user: &RecordId) -> Result<(), TrustError> {
    if !primary_email_verified(valence, user).await?
        || !primary_phone_verified(valence, user).await?
    {
        return Err(TrustError::ConfirmBlocked);
    }
    let row = load_user(valence, user).await?;
    if row.confirmed_at().is_some() {
        return Ok(());
    }
    let now = Utc::now();
    row.get_mutable_used(valence, valence::use_!(r"In **trust**, we **update this data** so later steps see the latest values for this workflow. Callers allowed for **trust** use the updated data; this is not a public export of unrelated fields."))
        .set_confirmed_at(now)
        .map_err(|_| TrustError::Store)?
        .set_updated_at(now)
        .map_err(|_| TrustError::Store)?
        .commit()
        .await
        .map_err(|_| TrustError::Store)?;
    Ok(())
}

/// System/admin stub: set `id_verified_at` (no ID vendor).
///
/// # Errors
///
/// Store / missing user.
pub async fn mark_user_id_verified(valence: &Valence, user: &RecordId) -> Result<(), TrustError> {
    let row = load_user(valence, user).await?;
    let now = Utc::now();
    row.get_mutable_used(valence, valence::use_!(r"In **trust**, we **update this data** so later steps see the latest values for this workflow. Callers allowed for **trust** use the updated data; this is not a public export of unrelated fields."))
        .set_id_verified_at(now)
        .map_err(|_| TrustError::Store)?
        .set_updated_at(now)
        .map_err(|_| TrustError::Store)?
        .commit()
        .await
        .map_err(|_| TrustError::Store)?;
    Ok(())
}
