//! Account confirm funnel server functions (status, phone OTP, confirm).

use leptos::prelude::*;

use crate::account_api::ConfirmAccountStatus;

/// Fetch confirm-funnel status for the signed-in user.
///
/// Uses `#[higgs_macros::server]` (operation attribution) plus
/// [`crate::ssr_support::require_auth_user`] for the product session gate.
/// `server(auth)` / `require_session` needs `SessionSnapshot` on every server-fn
/// POST; axum-login `AuthSession` is the reliable gate on current e2e hosts.
#[higgs_macros::server]
pub async fn get_confirm_account_status() -> Result<ConfirmAccountStatus, ServerFnError> {
    let (ctx, auth_user) = crate::ssr_support::require_auth_user().await?;
    let valence = ctx
        .unsafe_system_valence()
        .map_err(|e| crate::ssr_support::map_higgs_err(&e))?;

    let email_verified = crate::trust::primary_email_verified(&valence, &auth_user.id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let phone_verified = crate::trust::primary_phone_verified(&valence, &auth_user.id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let confirmed = crate::trust::is_confirmed(&valence, &auth_user.id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let masked_phone = load_masked_primary_phone(&valence, &auth_user.id).await?;

    Ok(ConfirmAccountStatus {
        masked_email: crate::account_api::mask_email_for_display(&auth_user.email),
        email_verified,
        masked_phone,
        phone_verified,
        confirmed,
    })
}

/// Issue an SMS OTP to `phone_e164` for the signed-in user.
///
/// Accepts common phone spellings; the server normalizes to E.164 before issue.
/// Returns the challenge id (not the OTP). Requires the `phone` feature at runtime.
#[higgs_macros::server]
pub async fn issue_phone_otp(
    /// Destination phone (E.164 or common national / punctuated forms).
    phone_e164: String,
) -> Result<String, ServerFnError> {
    #[cfg(not(feature = "phone"))]
    {
        let _ = phone_e164;
        let _ = crate::ssr_support::require_auth_user().await?;
        return Err(ServerFnError::new(
            "reason_class=unsupported: phone verification is not enabled",
        ));
    }
    #[cfg(feature = "phone")]
    {
        let (ctx, auth_user) = crate::ssr_support::require_auth_user().await?;
        let valence = ctx
            .unsafe_system_valence()
            .map_err(|e| crate::ssr_support::map_higgs_err(&e))?;
        let services =
            crate::services::auth_services().map_err(|e| ServerFnError::new(e.to_string()))?;
        let factors = crate::factor::FactorChallengeService::new(services);
        tracing::info!(
            operation = "phone_otp_issue",
            outcome = "start",
            "lepton_auth.confirm.phone_otp_issue"
        );
        let challenge_id = factors
            .issue_sms_otp(&valence, auth_user.id.clone(), phone_e164.trim())
            .await
            .map_err(|e| {
                tracing::warn!(
                    operation = "phone_otp_issue",
                    outcome = "error",
                    reason_class = e.reason_class(),
                    "lepton_auth.confirm.phone_otp_issue"
                );
                ServerFnError::new(e.to_string())
            })?;
        tracing::info!(
            operation = "phone_otp_issue",
            outcome = "ok",
            "lepton_auth.confirm.phone_otp_issue"
        );
        Ok(challenge_id)
    }
}

/// Verify an SMS OTP for `challenge_id`.
#[higgs_macros::server]
pub async fn verify_phone_otp(
    /// Challenge id returned from [`issue_phone_otp`].
    challenge_id: String,
    /// SMS one-time code.
    code: String,
) -> Result<(), ServerFnError> {
    #[cfg(not(feature = "phone"))]
    {
        let _ = (challenge_id, code);
        let _ = crate::ssr_support::require_auth_user().await?;
        return Err(ServerFnError::new(
            "reason_class=unsupported: phone verification is not enabled",
        ));
    }
    #[cfg(feature = "phone")]
    {
        let (ctx, _auth_user) = crate::ssr_support::require_auth_user().await?;
        let valence = ctx
            .unsafe_system_valence()
            .map_err(|e| crate::ssr_support::map_higgs_err(&e))?;
        let services =
            crate::services::auth_services().map_err(|e| ServerFnError::new(e.to_string()))?;
        let factors = crate::factor::FactorChallengeService::new(services);
        tracing::info!(
            operation = "phone_otp_verify",
            outcome = "start",
            "lepton_auth.confirm.phone_otp_verify"
        );
        let ok = factors
            .verify_sms_otp(challenge_id.trim(), code.trim(), &valence)
            .await
            .map_err(|e| {
                tracing::warn!(
                    operation = "phone_otp_verify",
                    outcome = "error",
                    reason_class = e.reason_class(),
                    "lepton_auth.confirm.phone_otp_verify"
                );
                ServerFnError::new(e.to_string())
            })?;
        if !ok {
            tracing::warn!(
                operation = "phone_otp_verify",
                outcome = "error",
                reason_class = "code_rejected",
                "lepton_auth.confirm.phone_otp_verify"
            );
            return Err(ServerFnError::new(
                "reason_class=code_rejected: verification code was not accepted",
            ));
        }
        tracing::info!(
            operation = "phone_otp_verify",
            outcome = "ok",
            "lepton_auth.confirm.phone_otp_verify"
        );
        Ok(())
    }
}

/// Confirm the signed-in account when primary email and phone are verified.
#[higgs_macros::server]
pub async fn confirm_account() -> Result<(), ServerFnError> {
    let (ctx, auth_user) = crate::ssr_support::require_auth_user().await?;
    let valence = ctx
        .unsafe_system_valence()
        .map_err(|e| crate::ssr_support::map_higgs_err(&e))?;

    tracing::info!(
        operation = "confirm_account",
        outcome = "start",
        "lepton_auth.confirm.confirm_account"
    );

    match crate::trust::confirm_user(&valence, &auth_user.id).await {
        Ok(()) => {
            #[cfg(feature = "spectra")]
            crate::spectra_emit::account(
                crate::spectra_emit::AccountOperation::Confirm,
                crate::spectra_emit::AuthOutcome::Success,
                "none",
            );
            tracing::info!(
                operation = "confirm_account",
                outcome = "ok",
                "lepton_auth.confirm.confirm_account"
            );
            Ok(())
        }
        Err(e) => {
            #[cfg(feature = "spectra")]
            crate::spectra_emit::account(
                crate::spectra_emit::AccountOperation::Confirm,
                crate::spectra_emit::AuthOutcome::Failure,
                e.reason_class(),
            );
            tracing::warn!(
                operation = "confirm_account",
                outcome = "error",
                reason_class = e.reason_class(),
                "lepton_auth.confirm.confirm_account"
            );
            Err(ServerFnError::new(e.to_string()))
        }
    }
}

#[cfg(feature = "ssr")]
async fn load_masked_primary_phone(
    valence: &valence::Valence,
    user: &valence::RecordId,
) -> Result<Option<String>, ServerFnError> {
    use lepton_host_adapter::generated::{AccountPhone, User};
    use valence::Model;

    let uid = valence::extract_id_from_record(user).unwrap_or_else(|_| user.id().to_string());
    let Some(row) = User::get_used(&uid, valence, valence::use_!(r#"In **actions**, we **load User** so the application can decide what to do next in this workflow. The result is used by **actions** logic—not necessarily displayed on a page unless that feature’s UI shows it."#))
        .await
        .map_err(|_| ServerFnError::new("reason_class=store: user load failed"))?
    else {
        return Ok(None);
    };
    let Some(primary) = row.primary_phone() else {
        return Ok(None);
    };
    let phone_id =
        valence::extract_id_from_record(primary).unwrap_or_else(|_| primary.id().to_string());
    let Some(phone) = AccountPhone::get_used(&phone_id, valence, valence::use_!(r#"In **actions**, we **load Account Phone** so the application can decide what to do next in this workflow. The result is used by **actions** logic—not necessarily displayed on a page unless that feature’s UI shows it."#))
        .await
        .map_err(|_| ServerFnError::new("reason_class=store: phone load failed"))?
    else {
        return Ok(None);
    };
    Ok(Some(crate::account_api::mask_phone_for_display(
        phone.e164(),
    )))
}
