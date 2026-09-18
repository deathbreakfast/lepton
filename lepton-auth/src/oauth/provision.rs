//! Create Account + User + `UserProfile` for OAuth signup (parity with email signup).

use chrono::Utc;
use lepton_host_adapter::generated::{
    Account, AccountEmail, AccountMembership, AccountMembershipRole, AccountPlan, AccountStatus,
    User, UserProfile, UserStatus, UserUserType,
};
use lepton_identity::ownership::{bare_id_from_record, ensure_signup_identity_ownership};
use valence::{Model, RecordId, Valence};

use super::error::OAuthError;
use crate::security::{display_name_policy_error, legal_name_policy_error};

/// Resolve legal + display names from provider hints.
///
/// Prefers `name_hint`, then email local-part, then `"User"`. Applies name policies;
/// falls back to a safe default when the hint fails policy.
pub(super) fn resolve_oauth_profile_names(
    email_hint: Option<&str>,
    name_hint: Option<&str>,
) -> (String, String) {
    let from_hint = name_hint
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let from_email = email_hint
        .and_then(|e| e.split('@').next())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let candidate = from_hint
        .clone()
        .or(from_email)
        .unwrap_or_else(|| "User".to_string());

    let legal_name = if legal_name_policy_error(&candidate).is_none() {
        candidate.clone()
    } else if let Some(ref h) = from_hint {
        if legal_name_policy_error(h).is_none() {
            h.clone()
        } else {
            "User".to_string()
        }
    } else {
        "User".to_string()
    };

    let display_candidate = from_hint.unwrap_or(candidate);
    let display_name = if display_name_policy_error(&display_candidate).is_none() {
        display_candidate
    } else {
        legal_name.clone()
    };

    (legal_name, display_name)
}

/// Create User (Active, no password) + optional email + Account/membership + `UserProfile`.
#[allow(clippy::too_many_lines)] // signup ladder: user + account + email + profile + membership
pub async fn create_oauth_user(
    valence: &Valence,
    email_hint: Option<&str>,
    name_hint: Option<&str>,
) -> Result<RecordId, OAuthError> {
    let (legal_name, display_name) = resolve_oauth_profile_names(email_hint, name_hint);
    let now = Utc::now();
    let user = User::new(
        Some(UserUserType::Person),
        None,
        Some(UserStatus::Active),
        None,
        None,
        None,
        None,
        None,
        now,
        now,
    )
    .map_err(|_| OAuthError::Store)?;
    let created = User::create_used(user, valence, valence::use_!(r"When **OAuth account linking** needs to persist work, we **save User** so the next step in that feature can continue with the latest values. People and services allowed for **OAuth account linking** use this data for that workflow—not as a general export of unrelated personal fields."))
        .await
        .map_err(|_| OAuthError::Store)?;
    let user_id = created.id().cloned().ok_or(OAuthError::Store)?;

    let account_label = email_hint.unwrap_or("oauth-user").to_string();
    let account = Account::new(
        account_label,
        user_id.clone(),
        Some(AccountPlan::Free),
        Some(AccountStatus::Active),
        None,
        None,
        now,
        now,
    )
    .map_err(|_| OAuthError::Store)?;
    let account_created = Account::create_used(account, valence, valence::use_!(r"When **OAuth account linking** needs to persist work, we **save Account** so the next step in that feature can continue with the latest values. People and services allowed for **OAuth account linking** use this data for that workflow—not as a general export of unrelated personal fields."))
        .await
        .map_err(|_| OAuthError::Store)?;
    let account_thing = account_created.id().cloned().ok_or(OAuthError::Store)?;

    let mut email_bare: Option<String> = None;
    if let Some(email) = email_hint {
        // Caller must check collision before create; free address only here.
        let row = AccountEmail::new(
            account_thing.clone(),
            email.to_string(),
            Some(now),
            now,
            now,
        )
        .map_err(|_| OAuthError::Store)?;
        let email_created = AccountEmail::create_used(row, valence, valence::use_!(r"When **OAuth account linking** needs to persist work, we **save Account Email** so the next step in that feature can continue with the latest values. People and services allowed for **OAuth account linking** use this data for that workflow—not as a general export of unrelated personal fields."))
            .await
            .map_err(|_| OAuthError::Store)?;
        if let Some(email_id) = email_created.id().cloned() {
            email_bare = Some(bare_id_from_record(&email_id));
            account_created
                .get_mutable_used(valence, valence::use_!(r"In **oauth**, we **update this data** so later steps see the latest values for this workflow. Callers allowed for **oauth** use the updated data; this is not a public export of unrelated fields."))
                .set_primary_email(email_id.clone())
                .map_err(|_| OAuthError::Store)?
                .set_updated_at(now)
                .map_err(|_| OAuthError::Store)?
                .commit()
                .await
                .map_err(|_| OAuthError::Store)?;
            created
                .get_mutable_used(valence, valence::use_!(r"In **oauth**, we **update this data** so later steps see the latest values for this workflow. Callers allowed for **oauth** use the updated data; this is not a public export of unrelated fields."))
                .set_primary_email(email_id)
                .map_err(|_| OAuthError::Store)?
                .set_updated_at(now)
                .map_err(|_| OAuthError::Store)?
                .commit()
                .await
                .map_err(|_| OAuthError::Store)?;
        }
    }

    let profile = UserProfile::new(user_id.clone(), legal_name, display_name, now, now, None)
        .map_err(|_| OAuthError::Store)?;
    let created_profile = UserProfile::create_used(profile, valence, valence::use_!(r"When **OAuth account linking** needs to persist work, we **save User Profile** so the next step in that feature can continue with the latest values. People and services allowed for **OAuth account linking** use this data for that workflow—not as a general export of unrelated personal fields."))
        .await
        .map_err(|_| OAuthError::Store)?;
    let profile_bare = bare_id_from_record(created_profile.id().ok_or(OAuthError::Store)?);

    let membership = AccountMembership::new(
        account_thing.clone(),
        user_id.clone(),
        AccountMembershipRole::Owner,
        now,
        now,
    )
    .map_err(|_| OAuthError::Store)?;
    let created_membership = AccountMembership::create_used(membership, valence, valence::use_!(r"When **OAuth account linking** needs to persist work, we **save Account Membership** so the next step in that feature can continue with the latest values. People and services allowed for **OAuth account linking** use this data for that workflow—not as a general export of unrelated personal fields."))
        .await
        .map_err(|_| OAuthError::Store)?;
    let membership_bare = bare_id_from_record(created_membership.id().ok_or(OAuthError::Store)?);

    let user_bare = bare_id_from_record(&user_id);
    let account_bare = bare_id_from_record(&account_thing);
    let mut extra = vec![
        ("user_profile", profile_bare.as_str()),
        ("account_membership", membership_bare.as_str()),
    ];
    let email_owned;
    if let Some(eb) = email_bare {
        email_owned = eb;
        extra.push(("account_email", email_owned.as_str()));
    }
    ensure_signup_identity_ownership(valence, &user_bare, &account_bare, &extra)
        .await
        .map_err(|_| OAuthError::Store)?;

    Ok(user_id)
}

#[cfg(test)]
mod tests {
    use super::resolve_oauth_profile_names;

    #[test]
    fn resolve_prefers_name_hint() {
        let (legal, display) =
            resolve_oauth_profile_names(Some("a@example.test"), Some("Alex Rivera"));
        assert_eq!(legal, "Alex Rivera");
        assert_eq!(display, "Alex Rivera");
    }

    #[test]
    fn resolve_falls_back_to_email_local() {
        let (legal, display) = resolve_oauth_profile_names(Some("alex@example.test"), None);
        assert_eq!(display, "alex");
        // "alex" may fail legal (no capital?) — legal_name_policy requires a letter, "alex" is fine
        assert_eq!(legal, "alex");
    }

    #[test]
    fn resolve_default_user() {
        let (legal, display) = resolve_oauth_profile_names(None, None);
        assert_eq!(legal, "User");
        assert_eq!(display, "User");
    }
}
