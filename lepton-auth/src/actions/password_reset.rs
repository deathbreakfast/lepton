//! Server functions for requesting and completing a password reset.

use leptos::prelude::*;

/// Issue and email a password reset token for `email`, if a matching person account
/// exists. Always returns `Ok` to avoid leaking whether the email is registered.
#[server(RequestPasswordReset)]
pub async fn request_password_reset(
    /// Account email to send a reset link to (if registered).
    email: String,
) -> Result<(), ServerFnError> {
    use chrono::{Duration, Utc};
    use lepton_host_adapter::generated::{AccountEmail, PasswordResetToken, User, UserUserType};
    use valence::{Model, StringPredicate};

    use crate::security::{log_credential_audit, random_token_part};

    let ctx = higgs::Higgs::from_request().await?;

    let email = email.trim().to_string();
    if email.is_empty() {
        return Err(ServerFnError::Args("Missing email".into()));
    }

    let valence = ctx
        .unsafe_system_valence()
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let maybe_email = AccountEmail::query(&valence, valence::use_!(r"In **password reset**, we **list Account Email** so the product can show or process the matching set for this workflow. Callers allowed for **password reset** use the list; it is not a public dump of every field to anonymous visitors."))
        .where_address(StringPredicate::Equals(email.clone()))
        .first()
        .await
        .map_err(|e| ServerFnError::new(format!("Failed to query user email: {e}")))?;

    let maybe_user = if let Some(row) = maybe_email {
        match row.id().cloned() {
            Some(email_id) => User::query(&valence, valence::use_!(r"In **password reset**, we **list User** so the product can show or process the matching set for this workflow. Callers allowed for **password reset** use the list; it is not a public dump of every field to anonymous visitors."))
                .where_primary_email(valence::RecordPredicate::Equals(email_id))
                .first()
                .await
                .map_err(|e| ServerFnError::new(format!("Failed to load user: {e}")))?,
            None => None,
        }
    } else {
        None
    };

    if let Some(user) = maybe_user {
        if matches!(user.user_type().cloned(), Some(UserUserType::Person)) {
            let token_id = random_token_part(12);
            let secret_hash = lepton_host_adapter::auth::hash_password(&token_id)
                .map_err(|e| ServerFnError::new(format!("Failed to hash reset token: {e}")))?;

            let Some(user_thing) = user.id().cloned() else {
                return Err(ServerFnError::new("User record is missing ID"));
            };

            let token = PasswordResetToken::new(
                user_thing,
                secret_hash,
                Utc::now() + Duration::minutes(30),
                None,
                Utc::now(),
            )
            .map_err(|e| ServerFnError::new(format!("Failed to build reset token: {e}")))?;

            PasswordResetToken::upsert(&token_id, token, &valence, valence::use_!(r"When **password reset** needs to persist work, we **save Password Reset Token** so the next step in that feature can continue with the latest values. People and services allowed for **password reset** use this data for that workflow—not as a general export of unrelated personal fields."))
                .await
                .map_err(|e| ServerFnError::new(format!("Failed to save reset token: {e}")))?;

            // Never surface SMTP/config failures to the client — they would distinguish
            // registered accounts from unknown emails (always-Ok anti-enumeration).
            // Quiet helper logs without recipient; audit uses masked email.
            log_credential_audit(
                "password_reset_requested",
                Some(email.as_str()),
                "success",
                Some("token_created_delivery_attempted"),
            );
            #[cfg(feature = "email")]
            {
                use crate::email_delivery::ssr::send_password_reset_token_email_quiet;
                send_password_reset_token_email_quiet(&email, &token_id).await;
            }
            #[cfg(not(feature = "email"))]
            {
                let _ = token_id;
            }
            #[cfg(feature = "spectra")]
            crate::spectra_emit::password_reset(
                crate::spectra_emit::PasswordResetStage::Request,
                crate::spectra_emit::AuthOutcome::Success,
                "none",
            );
        }
    }

    Ok(())
}

/// Validate a password reset token and set the associated user's new password.
#[server(ResetPassword)]
pub async fn reset_password(
    /// Password-reset token from the emailed link.
    token: String,
    /// Desired new password (must satisfy policy).
    new_password: String,
    /// Confirmation of `new_password`.
    confirm_password: String,
) -> Result<(), ServerFnError> {
    use chrono::Utc;
    use lepton_host_adapter::generated::User;
    use valence::{extract_id_from_record, Model};

    use crate::security::log_credential_audit;

    if token.trim().is_empty() || new_password.is_empty() || confirm_password.is_empty() {
        #[cfg(feature = "spectra")]
        crate::spectra_emit::password_reset(
            crate::spectra_emit::PasswordResetStage::Confirm,
            crate::spectra_emit::AuthOutcome::Failure,
            "validation",
        );
        return Err(ServerFnError::Args("Missing fields".into()));
    }
    if new_password != confirm_password {
        #[cfg(feature = "spectra")]
        crate::spectra_emit::password_reset(
            crate::spectra_emit::PasswordResetStage::Confirm,
            crate::spectra_emit::AuthOutcome::Failure,
            "validation",
        );
        return Err(ServerFnError::Args("Passwords do not match".into()));
    }
    if let Some(policy_error) = crate::security::password_policy_error_message(&new_password) {
        return Err(ServerFnError::Args(policy_error));
    }

    let token_id = token.trim();

    let ctx = higgs::Higgs::from_request().await?;
    // Token consume + password write require SYSTEM_ONLY policies.
    let valence = ctx
        .unsafe_system_valence()
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Consume the token before writing the password so concurrent resets cannot
    // both pass lifecycle checks (CAS via unique consume marker).
    let Some(reset_record) =
        crate::token_helpers::try_consume_password_reset_token(token_id, &token, &valence).await?
    else {
        #[cfg(feature = "spectra")]
        crate::spectra_emit::password_reset(
            crate::spectra_emit::PasswordResetStage::Confirm,
            crate::spectra_emit::AuthOutcome::Failure,
            "token",
        );
        return Err(ServerFnError::Args("Invalid or expired reset token".into()));
    };

    let user_id = extract_id_from_record(reset_record.user())
        .map_err(|e| ServerFnError::new(format!("Invalid user ref on reset token: {e}")))?;
    let user = User::get(&user_id, &valence, valence::use_!(r"In **password reset**, we **load User** so the application can decide what to do next in this workflow. The result is used by **password reset** logic—not necessarily displayed on a page unless that feature’s UI shows it."))
        .await
        .map_err(|e| ServerFnError::new(format!("Failed to load user: {e}")))?;
    let Some(user) = user else {
        return Err(ServerFnError::new("User not found for reset token"));
    };

    let new_hash = lepton_host_adapter::auth::hash_password(&new_password)
        .map_err(|e| ServerFnError::new(format!("Failed to hash password: {e}")))?;

    user.get_mutable(&valence, valence::use_!(r"In **actions**, we **update this data** so later steps see the latest values for this workflow. Callers allowed for **actions** use the updated data; this is not a public export of unrelated fields."))
        .set_password_hash(new_hash)
        .map_err(|e| ServerFnError::new(format!("Failed to set new hash: {e}")))?
        .set_updated_at(Utc::now())
        .map_err(|e| ServerFnError::new(format!("Failed to set updated_at: {e}")))?
        .commit()
        .await
        .map_err(|e| ServerFnError::new(format!("Failed to update password: {e}")))?;

    log_credential_audit(
        "password_reset_completed",
        None,
        "success",
        Some("password_updated"),
    );

    #[cfg(feature = "spectra")]
    crate::spectra_emit::password_reset(
        crate::spectra_emit::PasswordResetStage::Confirm,
        crate::spectra_emit::AuthOutcome::Success,
        "none",
    );
    Ok(())
}
