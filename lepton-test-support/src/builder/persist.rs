//! Core identity graph writes for [`super::TestUserBuilder`].

use chrono::Utc;
use lepton_host_adapter::auth::hash_password;
use lepton_host_adapter::generated::{
    Account, AccountEmail, AccountMembership, AccountMembershipRole, AccountPlan, AccountStatus,
    User as IdentityUser, UserStatus, UserUserType,
};
use valence::{Model, RecordId, Valence};

use crate::error::SeedError;

pub(super) async fn create_user_account_email(
    valence: &Valence,
    email: &str,
    password: &str,
    verified: bool,
) -> Result<(RecordId, RecordId, RecordId), SeedError> {
    let password_hash = hash_password(password).map_err(|_| SeedError::Crypto {
        operation: "hash_password",
    })?;
    let (user_id, created_user) = create_active_user(valence, password_hash).await?;
    let (account_id, created_account) = create_owner_account(valence, email, &user_id).await?;
    let email_id = attach_primary_email(
        valence,
        email,
        verified,
        &created_user,
        &created_account,
        &account_id,
    )
    .await?;
    Ok((user_id, account_id, email_id))
}

async fn create_active_user(
    valence: &Valence,
    password_hash: String,
) -> Result<(RecordId, IdentityUser), SeedError> {
    let now = Utc::now();
    let user = IdentityUser::new(
        Some(UserUserType::Person),
        Some(password_hash),
        Some(UserStatus::Active),
        None,
        None,
        None,
        None,
        None,
        now,
        now,
    )
    .map_err(|_| SeedError::Persistence {
        operation: "user_new",
    })?;
    let created =
        IdentityUser::create_used(user, valence, valence::use_!(r"When **builder** needs to persist work, we **save Identity User** so the next step in that feature can continue with the latest values. People and services allowed for **builder** use this data for that workflow—not as a general export of unrelated personal fields."))
            .await
            .map_err(|_| SeedError::Persistence {
                operation: "user_create",
            })?;
    let user_id = created.id().cloned().ok_or(SeedError::Persistence {
        operation: "user_id",
    })?;
    Ok((user_id, created))
}

async fn create_owner_account(
    valence: &Valence,
    email: &str,
    user_id: &RecordId,
) -> Result<(RecordId, Account), SeedError> {
    let now = Utc::now();
    let account = Account::new(
        email.to_string(),
        user_id.clone(),
        Some(AccountPlan::Free),
        Some(AccountStatus::Active),
        None,
        None,
        now,
        now,
    )
    .map_err(|_| SeedError::Persistence {
        operation: "account_new",
    })?;
    let account_created =
        Account::create_used(account, valence, valence::use_!(r"When **builder** needs to persist work, we **save Account** so the next step in that feature can continue with the latest values. People and services allowed for **builder** use this data for that workflow—not as a general export of unrelated personal fields."))
            .await
            .map_err(|_| SeedError::Persistence {
                operation: "account_create",
            })?;
    let account_id = account_created
        .id()
        .cloned()
        .ok_or(SeedError::Persistence {
            operation: "account_id",
        })?;

    let membership = AccountMembership::new(
        account_id.clone(),
        user_id.clone(),
        AccountMembershipRole::Owner,
        now,
        now,
    )
    .map_err(|_| SeedError::Persistence {
        operation: "membership_new",
    })?;
    AccountMembership::create_used(membership, valence, valence::use_!(r"When **builder** needs to persist work, we **save Account Membership** so the next step in that feature can continue with the latest values. People and services allowed for **builder** use this data for that workflow—not as a general export of unrelated personal fields."))
        .await
        .map_err(|_| SeedError::Persistence {
            operation: "membership_create",
        })?;
    Ok((account_id, account_created))
}

async fn attach_primary_email(
    valence: &Valence,
    email: &str,
    verified: bool,
    created_user: &IdentityUser,
    created_account: &Account,
    account_id: &RecordId,
) -> Result<RecordId, SeedError> {
    let now = Utc::now();
    let verified_at = verified.then_some(now);
    let email_row = AccountEmail::new(account_id.clone(), email.to_string(), verified_at, now, now)
        .map_err(|_| SeedError::Persistence {
            operation: "email_new",
        })?;
    let email_created = AccountEmail::create_used(email_row, valence, valence::use_!(r"When **builder** needs to persist work, we **save Account Email** so the next step in that feature can continue with the latest values. People and services allowed for **builder** use this data for that workflow—not as a general export of unrelated personal fields."))
        .await
        .map_err(|_| SeedError::Persistence {
            operation: "email_create",
        })?;
    let email_id = email_created.id().cloned().ok_or(SeedError::Persistence {
        operation: "email_id",
    })?;

    created_account
        .get_mutable_used(valence, valence::use_!(r"In **builder**, we **update this data** so later steps see the latest values for this workflow. Callers allowed for **builder** use the updated data; this is not a public export of unrelated fields."))
        .set_primary_email(email_id.clone())
        .map_err(|_| SeedError::Persistence {
            operation: "account_set_primary_email",
        })?
        .set_updated_at(now)
        .map_err(|_| SeedError::Persistence {
            operation: "account_set_updated_at",
        })?
        .commit()
        .await
        .map_err(|_| SeedError::Persistence {
            operation: "account_commit",
        })?;

    created_user
        .get_mutable_used(valence, valence::use_!(r"In **builder**, we **update this data** so later steps see the latest values for this workflow. Callers allowed for **builder** use the updated data; this is not a public export of unrelated fields."))
        .set_primary_email(email_id.clone())
        .map_err(|_| SeedError::Persistence {
            operation: "user_set_primary_email",
        })?
        .set_updated_at(now)
        .map_err(|_| SeedError::Persistence {
            operation: "user_set_updated_at",
        })?
        .commit()
        .await
        .map_err(|_| SeedError::Persistence {
            operation: "user_commit",
        })?;

    Ok(email_id)
}

/// Derive a stable lab E.164 from an email (same algorithm as the auth UI harness).
#[must_use]
pub fn unique_e164(email: &str) -> String {
    let digits: String = email
        .chars()
        .filter(char::is_ascii_digit)
        .take(10)
        .collect();
    let suffix = if digits.len() >= 4 {
        digits[digits.len().saturating_sub(4)..].to_string()
    } else {
        format!("{:04}", email.len() % 10_000)
    };
    format!("+1555555{suffix}")
}
