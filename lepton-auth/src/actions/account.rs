//! Server functions for the account settings page (overview, password, email changes).

use leptos::prelude::*;

/// Fetch the signed-in user's [`crate::account_api::AccountSettingsOverview`].
#[server(GetAccountSettingsOverview)]
pub async fn get_account_settings_overview(
) -> Result<crate::account_api::AccountSettingsOverview, ServerFnError> {
    let (_ctx, auth_user) = crate::ssr_support::require_auth_user().await?;
    Ok(crate::account_api::ssr::build_account_settings_overview(
        &auth_user,
    ))
}

/// Change the signed-in user's password after verifying the current password.
#[server(ChangePassword)]
pub async fn change_password(
    /// Existing password for verification.
    current_password: String,
    /// Desired new password (must satisfy policy).
    new_password: String,
    /// Confirmation of `new_password`.
    confirm_password: String,
) -> Result<(), ServerFnError> {
    let (ctx, auth_user) = crate::ssr_support::require_auth_user().await?;
    let valence = crate::ssr_support::user_valence(&ctx)?;

    crate::account_api::ssr::execute_change_password(
        &valence,
        &auth_user,
        crate::account_api::ssr::ChangePasswordRequest {
            current_password,
            new_password,
            confirm_password,
        },
    )
    .await?;

    // Password change rotates the credential-bound session stamp; drop any open
    // TOTP sudo window so Tier A gates require a fresh step-up (TM-3).
    let session: tower_sessions::Session = leptos_axum::extract().await?;
    crate::session_binding::clear_step_up_window(&session).await;
    Ok(())
}

/// Request a change to the signed-in user's email; sends a verification code to
/// `new_email` after checking `current_password`.
#[server(RequestEmailChange)]
pub async fn request_email_change(
    /// Email address to switch to after verification.
    new_email: String,
    /// Current password for verification.
    current_password: String,
) -> Result<(), ServerFnError> {
    let (ctx, auth_user) = crate::ssr_support::require_auth_user().await?;
    // AccountEmail create + verification token issue are SYSTEM_ONLY.
    let valence = ctx
        .unsafe_system_valence()
        .map_err(|e| crate::ssr_support::map_higgs_err(&e))?;

    crate::account_api::ssr::execute_request_email_change(
        &valence,
        &auth_user,
        crate::account_api::ssr::RequestEmailChangeRequest {
            new_email,
            current_password,
        },
    )
    .await
}

/// Send a fresh verification email for the signed-in user's current email address.
#[server(RequestEmailVerification)]
pub async fn request_email_verification() -> Result<(), ServerFnError> {
    let (ctx, auth_user) = crate::ssr_support::require_auth_user().await?;
    // Token issue is SYSTEM_ONLY (same as signup / password-reset token paths).
    let valence = ctx
        .unsafe_system_valence()
        .map_err(|e| crate::ssr_support::map_higgs_err(&e))?;
    crate::account_api::ssr::execute_request_email_verification(&valence, &auth_user).await
}

/// Validate an emailed verification token for the signed-in user and, if valid, mark
/// their email verified (applying a pending email change if one is attached).
#[server(VerifyEmailToken)]
#[allow(clippy::too_many_lines)]
pub async fn verify_email_token(
    /// One-time email verification token from the confirmation link.
    token: String,
) -> Result<(), ServerFnError> {
    use crate::contacts::{
        mark_account_email_verified, set_account_primary_email, set_primary_email, ContactError,
    };
    use crate::security::log_credential_audit;
    use crate::token_helpers::{
        ensure_token_lifecycle_valid, try_consume_email_verification_token, verify_token_secret,
        TokenLifecycleError,
    };
    use chrono::Utc;
    use lepton_host_adapter::generated::{AccountEmail, EmailVerificationToken, UserStatus};
    use valence::Model;

    let token_id = token.trim().to_string();
    if token_id.is_empty() {
        return Err(ServerFnError::Args("Missing token".into()));
    }

    let (ctx, auth_user) = crate::ssr_support::require_auth_user().await?;
    // Token load/consume + contact verify writes use SYSTEM_ONLY policies.
    let valence = ctx
        .unsafe_system_valence()
        .map_err(|e| crate::ssr_support::map_higgs_err(&e))?;

    let token_record = EmailVerificationToken::get(&token_id, &valence)
        .await
        .map_err(|e| ServerFnError::new(format!("Failed to load verification token: {e}")))?
        .ok_or_else(|| {
            log_credential_audit(
                "email_verification",
                Some(auth_user.email.as_str()),
                "failure",
                Some("invalid"),
            );
            ServerFnError::new(TokenLifecycleError::Invalid.message().to_string())
        })?;

    if token_record.user() != &auth_user.id {
        log_credential_audit(
            "email_verification",
            Some(auth_user.email.as_str()),
            "failure",
            Some("token_user_mismatch"),
        );
        return Err(ServerFnError::new(
            TokenLifecycleError::Invalid.message().to_string(),
        ));
    }

    if let Err(err) = ensure_token_lifecycle_valid(&token_record) {
        let detail = match err {
            TokenLifecycleError::Used => "used",
            TokenLifecycleError::Expired => "expired",
            TokenLifecycleError::Invalid => "invalid",
        };
        log_credential_audit(
            "email_verification",
            Some(auth_user.email.as_str()),
            "failure",
            Some(detail),
        );
        return Err(ServerFnError::new(err.message().to_string()));
    }
    if let Err(err) = verify_token_secret(&token_id, token_record.token_hash()) {
        log_credential_audit(
            "email_verification",
            Some(auth_user.email.as_str()),
            "failure",
            Some("invalid"),
        );
        return Err(ServerFnError::new(err.message().to_string()));
    }

    let consumed = try_consume_email_verification_token(&token_id, &valence).await?;
    if !consumed {
        let latest = EmailVerificationToken::get(&token_id, &valence)
            .await
            .map_err(|e| ServerFnError::new(format!("Failed to reload verification token: {e}")))?;
        let err = latest.map_or(TokenLifecycleError::Invalid, |latest_token| {
            ensure_token_lifecycle_valid(&latest_token)
                .err()
                .unwrap_or(TokenLifecycleError::Used)
        });
        let detail = match err {
            TokenLifecycleError::Used => "used",
            TokenLifecycleError::Expired => "expired",
            TokenLifecycleError::Invalid => "invalid",
        };
        log_credential_audit(
            "email_verification",
            Some(auth_user.email.as_str()),
            "failure",
            Some(detail),
        );
        return Err(ServerFnError::new(err.message().to_string()));
    }

    let email_bare = valence::extract_id_from_record(token_record.user_email())
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let email_row = AccountEmail::get(&email_bare, &valence)
        .await
        .map_err(|e| ServerFnError::new(format!("Failed to load user email: {e}")))?
        .ok_or_else(|| ServerFnError::new("User email not found for verification token"))?;

    mark_account_email_verified(&valence, &email_row)
        .await
        .map_err(|e: ContactError| ServerFnError::new(e.to_string()))?;

    // Email-change / non-primary verify: promote this contact to login + account primary.
    if let Some(email_id) = email_row.id().cloned() {
        let _ = set_primary_email(&valence, token_record.user(), &email_id).await;
        let _ = set_account_primary_email(&valence, email_row.account(), &email_id).await;
    }

    let user = crate::account_api::ssr::load_user_from_token(&valence, token_record.user()).await?;
    user.get_mutable(&valence)
        .set_status(UserStatus::Active)
        .map_err(|e| ServerFnError::new(format!("Failed to update user status: {e}")))?
        .set_updated_at(Utc::now())
        .map_err(|e| ServerFnError::new(format!("Failed to update timestamp: {e}")))?
        .commit()
        .await
        .map_err(|e| ServerFnError::new(format!("Failed to persist user update: {e}")))?;

    log_credential_audit(
        "email_verification",
        Some(auth_user.email.as_str()),
        "success",
        Some("verified"),
    );

    crate::events::publish_verification_completed(token_id, crate::events::VerificationKind::Email)
        .await;

    Ok(())
}

/// Removed tokenless email verification. Always returns an error so older
/// clients that still POST this server fn get a clear failure instead of a
/// missing route. Wire name stays `DebugMarkEmailVerified` for compatibility.
#[server(DebugMarkEmailVerified)]
#[allow(clippy::unused_async)] // `#[server]` functions must be async.
pub async fn mark_email_verified_unavailable() -> Result<(), ServerFnError> {
    Err(ServerFnError::ServerError(
        "Tokenless email verification is not available".into(),
    ))
}

/// Wipe the signed-in owner's legal account (`erase_account`), then log out.
///
/// Requires current password, confirm phrase `DELETE`, and a TOTP code when enrolled.
#[server(WipeAccount)]
pub async fn wipe_account(
    /// Current password for re-check.
    current_password: String,
    /// Must be the literal `DELETE`.
    confirm_phrase: String,
    /// Authenticator code when TOTP is enrolled; empty when not enrolled.
    totp_code: String,
) -> Result<(), ServerFnError> {
    use crate::routes::{auth_redirect_path, sanitize_referer_path};
    use leptos_axum::extract;

    let (ctx, auth_user) = crate::ssr_support::require_auth_user().await?;
    let valence = ctx
        .unsafe_system_valence()
        .map_err(|e| crate::ssr_support::map_higgs_err(&e))?;

    let totp_code = {
        let trimmed = totp_code.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    };

    crate::account_api::ssr::execute_wipe_account(
        &valence,
        &auth_user,
        crate::account_api::ssr::WipeAccountRequest {
            current_password,
            confirm_phrase,
            totp_code,
        },
    )
    .await?;

    // Session must not remain authenticated after identity removal.
    let mut auth_session: axum_login::AuthSession<lepton_host_adapter::auth::Backend> =
        extract().await?;
    if let Err(e) = auth_session.logout().await {
        return Err(ServerFnError::ServerError(format!("Logout failed: {e}")));
    }
    let session: tower_sessions::Session = extract().await?;
    session.remove::<String>("account_email").await?;
    leptos_axum::redirect(&auth_redirect_path(sanitize_referer_path(Some("/".into()))));
    Ok(())
}
