//! Account settings overview + server-side account mutation logic.

use serde::{Deserialize, Serialize};

/// Client-facing summary shown on the account settings page.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountSettingsOverview {
    /// Partially-masked email for display (see [`mask_email_for_display`]).
    pub masked_email: String,
    /// Whether the account's email has been verified.
    pub email_verified: bool,
    /// Highest role badge for the user (see [`role_badge_from_roles`]).
    pub role_badge: String,
}

/// Pick the highest-priority role badge (`super_admin` > `owner` > `admin` > `member`).
pub fn role_badge_from_roles(roles: &[String]) -> String {
    if roles.iter().any(|r| r == "super_admin") {
        "super_admin".to_string()
    } else if roles.iter().any(|r| r == "owner") {
        "owner".to_string()
    } else if roles.iter().any(|r| r == "admin") {
        "admin".to_string()
    } else {
        "member".to_string()
    }
}

/// Mask an email's local part for display (e.g. `jo****@example.com`).
pub fn mask_email_for_display(email: &str) -> String {
    let Some((local, domain)) = email.split_once('@') else {
        return "****".to_string();
    };

    let prefix: String = local.chars().take(2).collect();
    if prefix.is_empty() {
        return format!("em****@{domain}");
    }

    format!("{prefix}****@{domain}")
}

/// Mask an E.164 phone for display (keep country code + last 4 digits).
pub fn mask_phone_for_display(e164: &str) -> String {
    let digits: String = e164
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '+')
        .collect();
    if digits.len() <= 4 {
        return "****".to_string();
    }
    let (prefix, rest) = digits.split_at(digits.len().saturating_sub(4));
    let keep = prefix.chars().take(2).collect::<String>();
    format!("{keep}•••{rest}")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod confirm_status_tests {
    use super::*;

    #[test]
    fn mask_phone_keeps_prefix_and_last_four_happy() {
        assert_eq!(mask_phone_for_display("+15555550123"), "+1•••0123");
    }

    #[test]
    fn mask_phone_short_sad() {
        assert_eq!(mask_phone_for_display("12"), "****");
    }

    #[test]
    fn confirm_account_status_roundtrip_happy() {
        let status = ConfirmAccountStatus {
            masked_email: "ab****@example.com".into(),
            email_verified: true,
            masked_phone: Some("+1•••9999".into()),
            phone_verified: false,
            confirmed: false,
        };
        let json = serde_json::to_string(&status).expect("ser");
        let back: ConfirmAccountStatus = serde_json::from_str(&json).expect("de");
        assert_eq!(back, status);
    }
}

/// Client-facing status for the account confirm funnel / drop-in prompt.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfirmAccountStatus {
    /// Masked primary email (empty when unset).
    pub masked_email: String,
    /// Whether the primary email is verified.
    pub email_verified: bool,
    /// Masked primary phone when present.
    pub masked_phone: Option<String>,
    /// Whether the primary phone is verified.
    pub phone_verified: bool,
    /// Whether `User.confirmed_at` is set.
    pub confirmed: bool,
}

/// Confirm phrase required by account wipe (`execute_wipe_account` / host wipe UI).
pub const WIPE_CONFIRM_PHRASE: &str = "DELETE";

/// Server-side account settings mutations (change password, change/verify email).
#[cfg(feature = "ssr")]
pub mod ssr {
    use argon2::{password_hash::PasswordHash, PasswordVerifier};
    use chrono::Utc;
    use lepton_host_adapter::generated::{AccountEmail, User};
    use leptos::prelude::ServerFnError;
    use valence::{Model, StringPredicate, Valence};

    use crate::security::log_credential_audit;

    use super::{mask_email_for_display, role_badge_from_roles, AccountSettingsOverview};

    /// Request payload for [`execute_change_password`].
    pub struct ChangePasswordRequest {
        /// Current password, verified before the change is applied.
        pub current_password: String,
        /// Desired new password.
        pub new_password: String,
        /// Confirmation of the new password (must match `new_password`).
        pub confirm_password: String,
    }

    /// Request payload for [`execute_request_email_change`].
    pub struct RequestEmailChangeRequest {
        /// New email address to change to.
        pub new_email: String,
        /// Current password, verified before the change is requested.
        pub current_password: String,
    }

    /// Request payload for [`execute_wipe_account`].
    pub struct WipeAccountRequest {
        /// Current password, verified before erase.
        pub current_password: String,
        /// Must equal [`super::WIPE_CONFIRM_PHRASE`] (`DELETE`).
        pub confirm_phrase: String,
        /// TOTP code when the user has an enabled factor; ignored otherwise.
        pub totp_code: Option<String>,
    }

    /// Build the [`AccountSettingsOverview`] shown to `auth_user`.
    pub fn build_account_settings_overview(
        auth_user: &lepton_host_adapter::auth::User,
    ) -> AccountSettingsOverview {
        AccountSettingsOverview {
            masked_email: mask_email_for_display(&auth_user.email),
            email_verified: auth_user.email_verified,
            role_badge: role_badge_from_roles(&auth_user.roles),
        }
    }

    /// Verify the current password and, if valid and the new password satisfies policy,
    /// persist the new password hash.
    ///
    /// # Contract
    ///
    /// `valence` must be allowed to read `User.password_hash` for `auth_user`'s
    /// row (session User actor via `OWNER_BY_ID`, or System). Peer User actors
    /// see a stripped field and fail with "Current password is incorrect".
    pub async fn execute_change_password(
        valence: &Valence,
        auth_user: &lepton_host_adapter::auth::User,
        req: ChangePasswordRequest,
    ) -> Result<(), ServerFnError> {
        if req.current_password.is_empty()
            || req.new_password.is_empty()
            || req.confirm_password.is_empty()
        {
            #[cfg(feature = "spectra")]
            crate::spectra_emit::account(
                crate::spectra_emit::AccountOperation::ChangePassword,
                crate::spectra_emit::AuthOutcome::Failure,
                "validation",
            );
            return Err(ServerFnError::Args("Missing fields".into()));
        }
        if req.new_password != req.confirm_password {
            #[cfg(feature = "spectra")]
            crate::spectra_emit::account(
                crate::spectra_emit::AccountOperation::ChangePassword,
                crate::spectra_emit::AuthOutcome::Failure,
                "validation",
            );
            return Err(ServerFnError::Args("Passwords do not match".into()));
        }
        if let Some(policy_error) =
            crate::security::password_policy_error_message(&req.new_password)
        {
            return Err(ServerFnError::Args(policy_error));
        }

        let user_id = auth_user.id.to_string();
        let record_id = user_id.split(':').next_back().unwrap_or(&user_id);
        let user = User::get_used(record_id, valence, valence::use_!(r#"In **lepton auth**, we **load User** so the application can decide what to do next in this workflow. The result is used by **lepton auth** logic—not necessarily displayed on a page unless that feature’s UI shows it."#))
            .await
            .map_err(|e| ServerFnError::new(format!("Failed to load user: {e}")))?;
        let Some(user) = user else {
            return Err(ServerFnError::new("User not found"));
        };

        let Some(phc) = user.password_hash() else {
            return Err(ServerFnError::Args("Current password is incorrect".into()));
        };
        let parsed_hash = PasswordHash::new(phc)
            .map_err(|e| ServerFnError::new(format!("Stored hash is invalid: {e}")))?;
        if argon2::Argon2::default()
            .verify_password(req.current_password.as_bytes(), &parsed_hash)
            .is_err()
        {
            log_credential_audit(
                "password_change",
                Some(auth_user.email.as_str()),
                "failure",
                Some("current_password_invalid"),
            );
            #[cfg(feature = "spectra")]
            crate::spectra_emit::account(
                crate::spectra_emit::AccountOperation::ChangePassword,
                crate::spectra_emit::AuthOutcome::Failure,
                "invalid_credentials",
            );
            return Err(ServerFnError::Args("Current password is incorrect".into()));
        }

        let new_hash = lepton_host_adapter::auth::hash_password(&req.new_password)
            .map_err(|e| ServerFnError::new(format!("Failed to hash password: {e}")))?;

        user.get_mutable_used(valence, valence::use_!(r#"In **lepton auth**, we **update this data** so later steps see the latest values for this workflow. Callers allowed for **lepton auth** use the updated data; this is not a public export of unrelated fields."#))
            .set_password_hash(new_hash)
            .map_err(|e| ServerFnError::new(format!("Failed to set new hash: {e}")))?
            .set_updated_at(Utc::now())
            .map_err(|e| ServerFnError::new(format!("Failed to set updated_at: {e}")))?
            .commit()
            .await
            .map_err(|e| ServerFnError::new(format!("Failed to persist password: {e}")))?;

        log_credential_audit(
            "password_change",
            Some(auth_user.email.as_str()),
            "success",
            Some("password_updated"),
        );

        #[cfg(feature = "spectra")]
        crate::spectra_emit::account(
            crate::spectra_emit::AccountOperation::ChangePassword,
            crate::spectra_emit::AuthOutcome::Success,
            "none",
        );
        Ok(())
    }

    /// Verify permissions and the current password, then issue and email a verification
    /// token for the requested new email address.
    pub async fn execute_request_email_change(
        valence: &Valence,
        auth_user: &lepton_host_adapter::auth::User,
        req: RequestEmailChangeRequest,
    ) -> Result<(), ServerFnError> {
        let allowed_roles = ["owner", "admin", "super_admin"];
        if !auth_user
            .roles
            .iter()
            .any(|role| allowed_roles.contains(&role.as_str()))
        {
            return Err(ServerFnError::Args(
                "You do not have permission to change account email".into(),
            ));
        }

        let candidate = req.new_email.trim().to_lowercase();
        if candidate.is_empty() {
            return Err(ServerFnError::Args("New email is required".into()));
        }
        if candidate == auth_user.email.to_lowercase() {
            return Err(ServerFnError::Args("New email must be different".into()));
        }

        let user_id = auth_user.id.to_string();
        let record_id = user_id.split(':').next_back().unwrap_or(&user_id);
        let user = User::get_used(record_id, valence, valence::use_!(r#"In **lepton auth**, we **load User** so the application can decide what to do next in this workflow. The result is used by **lepton auth** logic—not necessarily displayed on a page unless that feature’s UI shows it."#))
            .await
            .map_err(|e| ServerFnError::new(format!("Failed to load user: {e}")))?
            .ok_or_else(|| ServerFnError::new("User not found"))?;

        let Some(phc) = user.password_hash() else {
            return Err(ServerFnError::Args("Current password is incorrect".into()));
        };
        let parsed_hash = PasswordHash::new(phc)
            .map_err(|e| ServerFnError::new(format!("Stored hash is invalid: {e}")))?;
        if argon2::Argon2::default()
            .verify_password(req.current_password.as_bytes(), &parsed_hash)
            .is_err()
        {
            return Err(ServerFnError::Args("Current password is incorrect".into()));
        }

        if AccountEmail::query_used(valence, valence::use_!(r#"In **lepton auth**, we **list Account Email** so the product can show or process the matching set for this workflow. Callers allowed for **lepton auth** use the list; it is not a public dump of every field to anonymous visitors."#))
            .where_address(StringPredicate::Equals(candidate.clone()))
            .first()
            .await
            .map_err(|e| ServerFnError::new(format!("Failed to query email availability: {e}")))?
            .is_some()
        {
            return Err(ServerFnError::Args("Email is already in use".into()));
        }

        #[cfg(not(feature = "email"))]
        {
            let _ = (valence, candidate);
            Err(ServerFnError::new(
                "reason_class=feature: email delivery not enabled",
            ))
        }
        #[cfg(feature = "email")]
        {
            use crate::contacts::{account_for_user, add_account_email};
            use crate::email_delivery::ssr::send_verification_token_email;
            use crate::token_helpers::issue_email_verification_token;
            use lepton_smtp::VerificationEmailFlow;

            let account = account_for_user(valence, &auth_user.id)
                .await
                .map_err(|e| ServerFnError::new(e.to_string()))?;
            let email_row = add_account_email(valence, &account, &candidate)
                .await
                .map_err(|e| ServerFnError::new(e.to_string()))?;
            let email_id = email_row
                .id()
                .cloned()
                .ok_or_else(|| ServerFnError::new("Account email missing id"))?;
            let token_id =
                issue_email_verification_token(valence, auth_user.id.clone(), email_id).await?;
            send_verification_token_email(
                &candidate,
                None,
                &token_id,
                VerificationEmailFlow::ChangeEmail,
            )
            .await?;
            tracing::info!(
                reason_class = "change_email",
                "change-email verification token delivered (recipients omitted)"
            );
            Ok(())
        }
    }

    /// Issue and email a fresh verification token for the signed-in user's current email.
    #[allow(clippy::unused_async)] // awaits only when the `email` feature is enabled
    pub async fn execute_request_email_verification(
        valence: &Valence,
        auth_user: &lepton_host_adapter::auth::User,
    ) -> Result<(), ServerFnError> {
        #[cfg(not(feature = "email"))]
        {
            let _ = (valence, auth_user);
            Err(ServerFnError::new(
                "reason_class=feature: email delivery not enabled",
            ))
        }
        #[cfg(feature = "email")]
        {
            use crate::email_delivery::ssr::send_verification_token_email_quiet;
            use crate::token_helpers::issue_email_verification_token;
            use lepton_smtp::VerificationEmailFlow;

            use crate::contacts::find_account_email_by_address;
            let email_row = find_account_email_by_address(valence, &auth_user.email)
                .await
                .map_err(|e| ServerFnError::new(e.to_string()))?
                .ok_or_else(|| ServerFnError::new("Primary email contact not found"))?;
            let email_id = email_row
                .id()
                .cloned()
                .ok_or_else(|| ServerFnError::new("User email missing id"))?;
            let token_id =
                issue_email_verification_token(valence, auth_user.id.clone(), email_id).await?;
            send_verification_token_email_quiet(
                &auth_user.email,
                None,
                &token_id,
                VerificationEmailFlow::Resend,
            )
            .await;
            tracing::info!(
                reason_class = "resend",
                "email verification resend requested (recipient omitted)"
            );
            Ok(())
        }
    }

    /// Load the [`User`] referenced by a token's `user` field.
    pub async fn load_user_from_token(
        valence: &Valence,
        user_record: &valence::RecordId,
    ) -> Result<User, ServerFnError> {
        let user_id = valence::extract_id_from_record(user_record)
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        User::get_used(&user_id, valence, valence::use_!(r#"In **lepton auth**, we **load User** so the application can decide what to do next in this workflow. The result is used by **lepton auth** logic—not necessarily displayed on a page unless that feature’s UI shows it."#))
            .await
            .map_err(|e| ServerFnError::new(format!("Failed to load user: {e}")))?
            .ok_or_else(|| ServerFnError::new("User not found for verification token"))
    }

    fn user_bare_id(auth_user: &lepton_host_adapter::auth::User) -> String {
        let user_id = auth_user.id.to_string();
        user_id
            .split(':')
            .next_back()
            .unwrap_or(&user_id)
            .to_string()
    }

    async fn verify_current_password(
        valence: &Valence,
        auth_user: &lepton_host_adapter::auth::User,
        current_password: &str,
        audit_flow: &str,
    ) -> Result<(), ServerFnError> {
        let record_id = user_bare_id(auth_user);
        let user = User::get_used(&record_id, valence, valence::use_!(r#"In **lepton auth**, we **load User** so the application can decide what to do next in this workflow. The result is used by **lepton auth** logic—not necessarily displayed on a page unless that feature’s UI shows it."#))
            .await
            .map_err(|e| ServerFnError::new(format!("Failed to load user: {e}")))?
            .ok_or_else(|| ServerFnError::new("User not found"))?;

        let Some(phc) = user.password_hash() else {
            return Err(ServerFnError::Args("Current password is incorrect".into()));
        };
        let parsed_hash = PasswordHash::new(phc)
            .map_err(|e| ServerFnError::new(format!("Stored hash is invalid: {e}")))?;
        if argon2::Argon2::default()
            .verify_password(current_password.as_bytes(), &parsed_hash)
            .is_err()
        {
            log_credential_audit(
                audit_flow,
                Some(auth_user.email.as_str()),
                "failure",
                Some("current_password_invalid"),
            );
            return Err(ServerFnError::Args("Current password is incorrect".into()));
        }
        Ok(())
    }

    /// Owner-gated GDPR wipe: password (+ TOTP when enrolled), then [`crate::identity_delete::erase_account`].
    ///
    /// `valence` must be System (or otherwise capable of Account / contact CUD). Authz is
    /// enforced here before erase — do not call with an unauthenticated actor.
    ///
    /// # Errors
    ///
    /// [`ServerFnError::Args`] for confirm phrase, role, password, or TOTP failures;
    /// server errors for store / erase failures.
    #[allow(clippy::too_many_lines)] // wipe authz ladder + optional Spectra emit
    pub async fn execute_wipe_account(
        valence: &Valence,
        auth_user: &lepton_host_adapter::auth::User,
        req: WipeAccountRequest,
    ) -> Result<(), ServerFnError> {
        use lepton_host_adapter::generated::{AccountMembership, AccountMembershipRole};
        use valence::{RecordId, RecordPredicate};

        use crate::identity_delete::erase_account;

        tracing::info!(
            operation = "account_wipe",
            outcome = "start",
            "lepton_auth.account.wipe"
        );

        if req.confirm_phrase.trim() != super::WIPE_CONFIRM_PHRASE {
            tracing::warn!(
                operation = "account_wipe",
                outcome = "error",
                reason_class = "confirm_phrase",
                "lepton_auth.account.wipe"
            );
            #[cfg(feature = "spectra")]
            crate::spectra_emit::account(
                crate::spectra_emit::AccountOperation::Wipe,
                crate::spectra_emit::AuthOutcome::Failure,
                "confirm_phrase",
            );
            return Err(ServerFnError::Args(
                "Type DELETE to confirm account wipe".into(),
            ));
        }

        if !auth_user.roles.iter().any(|role| role == "owner") {
            tracing::warn!(
                operation = "account_wipe",
                outcome = "error",
                reason_class = "not_owner",
                "lepton_auth.account.wipe"
            );
            #[cfg(feature = "spectra")]
            crate::spectra_emit::account(
                crate::spectra_emit::AccountOperation::Wipe,
                crate::spectra_emit::AuthOutcome::Failure,
                "not_owner",
            );
            return Err(ServerFnError::Args(
                "Only the account owner can wipe this account".into(),
            ));
        }

        if req.current_password.is_empty() {
            return Err(ServerFnError::Args("Missing fields".into()));
        }

        verify_current_password(valence, auth_user, &req.current_password, "account_wipe").await?;

        let memberships = AccountMembership::query_used(valence, valence::use_!(r#"In **lepton auth**, we **list Account Membership** so the product can show or process the matching set for this workflow. Callers allowed for **lepton auth** use the list; it is not a public dump of every field to anonymous visitors."#))
            .where_user(RecordPredicate::Equals(auth_user.id.clone()))
            .await
            .map_err(|e| ServerFnError::new(format!("Failed to load memberships: {e}")))?;
        let Some(membership) = memberships.into_iter().next() else {
            tracing::warn!(
                operation = "account_wipe",
                outcome = "error",
                reason_class = "not_member",
                "lepton_auth.account.wipe"
            );
            return Err(ServerFnError::Args(
                "Only the account owner can wipe this account".into(),
            ));
        };
        if *membership.role() != AccountMembershipRole::Owner {
            tracing::warn!(
                operation = "account_wipe",
                outcome = "error",
                reason_class = "not_owner",
                "lepton_auth.account.wipe"
            );
            return Err(ServerFnError::Args(
                "Only the account owner can wipe this account".into(),
            ));
        }
        let account: RecordId = membership.account().clone();

        #[cfg(feature = "totp")]
        {
            use lepton_host_adapter::generated::TotpFactor;

            use crate::factor::verify_totp_against_sealed;

            let uid = user_bare_id(auth_user);
            let factors = TotpFactor::get_from_user_id(&uid, valence)
                .await
                .map_err(|e| ServerFnError::new(format!("Failed to load TOTP factors: {e}")))?;
            if let Some(factor) = factors.into_iter().find(|f| f.enabled_at().is_some()) {
                let Some(code) = req
                    .totp_code
                    .as_deref()
                    .map(str::trim)
                    .filter(|c| !c.is_empty())
                else {
                    tracing::warn!(
                        operation = "account_wipe",
                        outcome = "error",
                        reason_class = "totp_required",
                        "lepton_auth.account.wipe"
                    );
                    #[cfg(feature = "spectra")]
                    crate::spectra_emit::account(
                        crate::spectra_emit::AccountOperation::Wipe,
                        crate::spectra_emit::AuthOutcome::Failure,
                        "totp_required",
                    );
                    return Err(ServerFnError::Args(
                        "Authenticator code is required to wipe this account".into(),
                    ));
                };
                if let Err(err) = verify_totp_against_sealed(factor.secret_sealed(), code, None) {
                    tracing::warn!(
                        operation = "account_wipe",
                        outcome = "error",
                        reason_class = err.reason_class(),
                        "lepton_auth.account.wipe"
                    );
                    return Err(ServerFnError::Args(
                        "Authenticator code is incorrect".into(),
                    ));
                }
            }
        }
        #[cfg(not(feature = "totp"))]
        {
            let _ = &req.totp_code;
        }

        if let Err(e) = erase_account(valence, &account).await {
            tracing::warn!(
                operation = "account_wipe",
                outcome = "error",
                reason_class = e.reason_class(),
                "lepton_auth.account.wipe"
            );
            #[cfg(feature = "spectra")]
            crate::spectra_emit::account(
                crate::spectra_emit::AccountOperation::Wipe,
                crate::spectra_emit::AuthOutcome::Failure,
                e.reason_class(),
            );
            return Err(ServerFnError::ServerError(format!(
                "Account wipe failed: {}",
                e.reason_class()
            )));
        }

        log_credential_audit(
            "account_wipe",
            Some(auth_user.email.as_str()),
            "success",
            Some("erased"),
        );
        tracing::info!(
            operation = "account_wipe",
            outcome = "ok",
            "lepton_auth.account.wipe"
        );
        #[cfg(feature = "spectra")]
        crate::spectra_emit::account(
            crate::spectra_emit::AccountOperation::Wipe,
            crate::spectra_emit::AuthOutcome::Success,
            "none",
        );
        Ok(())
    }
}
