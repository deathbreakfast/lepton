//! Server functions for TOTP enroll / disable / recovery (Account Settings).
//!
//! Signed-in product UI wraps [`crate::totp`] library APIs. Hosts show
//! `PendingTotpEnrollView::qr_svg` and `PendingTotpEnrollView::manual_secret`,
//! confirm with a code, then display recovery codes once.
//!
//! # Examples
//!
//! ```rust,ignore
//! use lepton_auth::actions::totp::{
//!     begin_totp_enroll_ui, confirm_totp_enroll_ui, get_totp_settings_status,
//! };
//!
//! async fn enroll_from_settings() -> Result<(), leptos::prelude::ServerFnError> {
//!     let status = get_totp_settings_status().await?;
//!     if !status.totp_enabled {
//!         let pending = begin_totp_enroll_ui().await?;
//!         // render pending.qr_svg; show pending.manual_secret
//!         let _recovery = confirm_totp_enroll_ui(pending.factor_id, "123456".into()).await?;
//!     }
//!     Ok(())
//! }
//! ```

use leptos::prelude::*;
use serde::{Deserialize, Serialize};

/// Client-facing TOTP enrollment status for Account Settings.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TotpSettingsStatus {
    /// Whether the signed-in user has an enabled TOTP factor.
    pub totp_enabled: bool,
}

/// Pending enroll payload for QR / manual entry (secrets returned once to the owner session).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[must_use]
pub struct PendingTotpEnrollView {
    /// Valence `totp_factor` id for [`confirm_totp_enroll_ui`].
    pub factor_id: String,
    /// Full `otpauth://` URI (also encoded in [`Self::qr_svg`]).
    pub otpauth_uri: String,
    /// Base32 secret for manual entry (may include spaces for readability).
    pub manual_secret: String,
    /// Server-rendered SVG markup for the QR.
    pub qr_svg: String,
}

#[cfg(all(feature = "ssr", feature = "totp"))]
fn map_enroll_err(err: crate::totp::TotpEnrollError) -> ServerFnError {
    use crate::totp::TotpEnrollError;
    match err {
        TotpEnrollError::Mismatch => {
            ServerFnError::new("Incorrect code. Try the current code from your app.")
        }
        TotpEnrollError::AlreadyEnabled => {
            ServerFnError::new("An authenticator is already set up on this account.")
        }
        TotpEnrollError::FactorMissing => {
            ServerFnError::new("That setup expired. Start authenticator setup again.")
        }
        other => ServerFnError::new(other.to_string()),
    }
}

#[cfg(all(feature = "ssr", feature = "totp"))]
#[allow(clippy::needless_pass_by_value)] // maps owned FactorChallengeError from Result paths
fn map_factor_err(err: crate::factor::FactorChallengeError) -> ServerFnError {
    if err.reason_class() == "mismatch" {
        ServerFnError::new("Incorrect code. Try the current code from your app.")
    } else {
        ServerFnError::new(err.to_string())
    }
}

#[cfg(all(feature = "ssr", feature = "totp"))]
async fn totp_system_valence(
) -> Result<(higgs::Higgs, lepton_host_adapter::User, valence::Valence), ServerFnError> {
    let (ctx, auth_user) = crate::ssr_support::require_auth_user().await?;
    let valence = ctx
        .unsafe_system_valence()
        .map_err(|e| crate::ssr_support::map_higgs_err(&e))?;
    Ok((ctx, auth_user, valence))
}

#[cfg(all(feature = "ssr", feature = "totp"))]
fn totp_issuer() -> String {
    // Host override for the otpauth issuer shown in authenticator apps during
    // Account Settings enroll. Live CLI uses `UF_LIVE_VERIFY_TOTP_ISSUER` instead.
    std::env::var("UF_TOTP_ISSUER")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Unified Field".to_string())
}

#[cfg(all(feature = "ssr", feature = "totp"))]
async fn user_has_enabled_totp(
    valence: &valence::Valence,
    user: &valence::RecordId,
) -> Result<bool, ServerFnError> {
    use lepton_host_adapter::generated::TotpFactor;
    let uid = valence::extract_id_from_record(user).unwrap_or_else(|_| user.id().to_string());
    let factors = TotpFactor::get_from_user_id(
        &uid,
        valence,
        valence::use_!(r"On your **authenticator settings**, we **list your factors** so the page can show whether setup is already enabled. Only you see that status for your account."),
    )
    .await
    .map_err(|_| ServerFnError::new("totp status unavailable"))?;
    Ok(factors.iter().any(|f| f.enabled_at().is_some()))
}

/// Whether the signed-in user has TOTP enabled.
#[server(GetTotpSettingsStatus)]
pub async fn get_totp_settings_status() -> Result<TotpSettingsStatus, ServerFnError> {
    #[cfg(not(feature = "totp"))]
    {
        let _ = crate::ssr_support::require_auth_user().await?;
        Ok(TotpSettingsStatus {
            totp_enabled: false,
        })
    }
    #[cfg(feature = "totp")]
    {
        tracing::info!(
            operation = "totp_status",
            outcome = "start",
            "lepton.totp.status_ui"
        );
        let (_ctx, auth_user, valence) = totp_system_valence().await?;
        let totp_enabled = user_has_enabled_totp(&valence, &auth_user.id)
            .await
            .inspect_err(|_| {
                tracing::warn!(
                    operation = "totp_status",
                    outcome = "error",
                    error_class = "store",
                    "lepton.totp.status_ui"
                );
            })?;
        tracing::info!(
            operation = "totp_status",
            outcome = "ok",
            "lepton.totp.status_ui"
        );
        Ok(TotpSettingsStatus { totp_enabled })
    }
}

/// Begin TOTP enrollment; returns otpauth URI, manual secret, and QR SVG.
#[server(BeginTotpEnrollUi)]
pub async fn begin_totp_enroll_ui() -> Result<PendingTotpEnrollView, ServerFnError> {
    #[cfg(not(feature = "totp"))]
    {
        let _ = crate::ssr_support::require_auth_user().await?;
        Err(ServerFnError::new(
            "Authenticator setup is not available on this host.",
        ))
    }
    #[cfg(feature = "totp")]
    {
        use crate::totp::{
            begin_totp_enroll, format_manual_secret, manual_secret_from_otpauth_uri,
            qr_svg_for_otpauth,
        };

        tracing::info!(
            operation = "totp_begin_enroll_ui",
            outcome = "start",
            "lepton.totp.begin_enroll_ui"
        );
        let (_ctx, auth_user, valence) = totp_system_valence().await?;
        let pending = begin_totp_enroll(
            &valence,
            &auth_user.id,
            auth_user.email.trim(),
            &totp_issuer(),
        )
        .await
        .map_err(|e| {
            tracing::warn!(
                operation = "totp_begin_enroll_ui",
                outcome = "error",
                error_class = e.reason_class(),
                "lepton.totp.begin_enroll_ui"
            );
            map_enroll_err(e)
        })?;
        let secret = manual_secret_from_otpauth_uri(&pending.otpauth_uri).ok_or_else(|| {
            tracing::warn!(
                operation = "totp_begin_enroll_ui",
                outcome = "error",
                error_class = "store",
                "lepton.totp.begin_enroll_ui"
            );
            ServerFnError::new("Could not prepare authenticator setup.")
        })?;
        let qr_svg = qr_svg_for_otpauth(&pending.otpauth_uri).map_err(|e| {
            tracing::warn!(
                operation = "totp_begin_enroll_ui",
                outcome = "error",
                error_class = e.reason_class(),
                "lepton.totp.begin_enroll_ui"
            );
            map_enroll_err(e)
        })?;
        tracing::info!(
            operation = "totp_begin_enroll_ui",
            outcome = "ok",
            "lepton.totp.begin_enroll_ui"
        );
        Ok(PendingTotpEnrollView {
            factor_id: pending.factor_id,
            otpauth_uri: pending.otpauth_uri,
            manual_secret: format_manual_secret(&secret),
            qr_svg,
        })
    }
}

/// Confirm enroll with a TOTP code; returns recovery codes once (regenerated).
#[server(ConfirmTotpEnrollUi)]
pub async fn confirm_totp_enroll_ui(
    /// Pending factor id from [`begin_totp_enroll_ui`].
    factor_id: String,
    /// Current authenticator code.
    code: String,
) -> Result<Vec<String>, ServerFnError> {
    #[cfg(not(feature = "totp"))]
    {
        let _ = (factor_id, code);
        let _ = crate::ssr_support::require_auth_user().await?;
        Err(ServerFnError::new(
            "Authenticator setup is not available on this host.",
        ))
    }
    #[cfg(feature = "totp")]
    {
        use crate::totp::{confirm_totp_enroll, regenerate_totp_recovery_codes};

        tracing::info!(
            operation = "totp_confirm_enroll_ui",
            outcome = "start",
            "lepton.totp.confirm_enroll_ui"
        );
        if code.trim().is_empty() || factor_id.trim().is_empty() {
            return Err(ServerFnError::Args("Missing code".into()));
        }
        let (_ctx, auth_user, valence) = totp_system_valence().await?;
        confirm_totp_enroll(&valence, &auth_user.id, factor_id.trim(), code.trim())
            .await
            .map_err(|e| {
                tracing::warn!(
                    operation = "totp_confirm_enroll_ui",
                    outcome = "error",
                    error_class = e.reason_class(),
                    "lepton.totp.confirm_enroll_ui"
                );
                map_enroll_err(e)
            })?;
        let codes = regenerate_totp_recovery_codes(&valence, &auth_user.id)
            .await
            .map_err(|e| {
                tracing::warn!(
                    operation = "totp_confirm_enroll_ui",
                    outcome = "error",
                    error_class = e.reason_class(),
                    "lepton.totp.confirm_enroll_ui"
                );
                map_enroll_err(e)
            })?;
        tracing::info!(
            operation = "totp_confirm_enroll_ui",
            outcome = "ok",
            "lepton.totp.confirm_enroll_ui"
        );
        Ok(codes)
    }
}

/// Disable TOTP after verifying a current authenticator code.
#[server(DisableTotpUi)]
pub async fn disable_totp_ui(
    /// Current authenticator code.
    code: String,
) -> Result<(), ServerFnError> {
    #[cfg(not(feature = "totp"))]
    {
        let _ = code;
        let _ = crate::ssr_support::require_auth_user().await?;
        Err(ServerFnError::new(
            "Authenticator setup is not available on this host.",
        ))
    }
    #[cfg(feature = "totp")]
    {
        use crate::factor::FactorChallengeService;
        use crate::totp::disable_totp;

        tracing::info!(
            operation = "totp_disable_ui",
            outcome = "start",
            "lepton.totp.disable_ui"
        );
        if code.trim().is_empty() {
            return Err(ServerFnError::Args("Missing code".into()));
        }
        let (_ctx, auth_user, valence) = totp_system_valence().await?;
        let services = crate::auth_services().map_err(|e| ServerFnError::new(e.to_string()))?;
        let factors = FactorChallengeService::new(services);
        factors
            .verify_totp_code(&valence, &auth_user.id, code.trim())
            .await
            .map_err(|e| {
                tracing::warn!(
                    operation = "totp_disable_ui",
                    outcome = "error",
                    error_class = e.reason_class(),
                    "lepton.totp.disable_ui"
                );
                map_factor_err(e)
            })?;
        disable_totp(&valence, &auth_user.id).await.map_err(|e| {
            tracing::warn!(
                operation = "totp_disable_ui",
                outcome = "error",
                error_class = e.reason_class(),
                "lepton.totp.disable_ui"
            );
            map_enroll_err(e)
        })?;
        tracing::info!(
            operation = "totp_disable_ui",
            outcome = "ok",
            "lepton.totp.disable_ui"
        );
        Ok(())
    }
}

/// Replace recovery codes after verifying a current authenticator code; returns plaintext once.
#[server(RegenerateTotpRecoveryCodesUi)]
pub async fn regenerate_totp_recovery_codes_ui(
    /// Current authenticator code.
    code: String,
) -> Result<Vec<String>, ServerFnError> {
    #[cfg(not(feature = "totp"))]
    {
        let _ = code;
        let _ = crate::ssr_support::require_auth_user().await?;
        Err(ServerFnError::new(
            "Authenticator setup is not available on this host.",
        ))
    }
    #[cfg(feature = "totp")]
    {
        use crate::factor::FactorChallengeService;
        use crate::totp::regenerate_totp_recovery_codes;

        tracing::info!(
            operation = "totp_regenerate_recovery_ui",
            outcome = "start",
            "lepton.totp.regenerate_recovery_ui"
        );
        if code.trim().is_empty() {
            return Err(ServerFnError::Args("Missing code".into()));
        }
        let (_ctx, auth_user, valence) = totp_system_valence().await?;
        let services = crate::auth_services().map_err(|e| ServerFnError::new(e.to_string()))?;
        let factors = FactorChallengeService::new(services);
        factors
            .verify_totp_code(&valence, &auth_user.id, code.trim())
            .await
            .map_err(|e| {
                tracing::warn!(
                    operation = "totp_regenerate_recovery_ui",
                    outcome = "error",
                    error_class = e.reason_class(),
                    "lepton.totp.regenerate_recovery_ui"
                );
                map_factor_err(e)
            })?;
        let codes = regenerate_totp_recovery_codes(&valence, &auth_user.id)
            .await
            .map_err(|e| {
                tracing::warn!(
                    operation = "totp_regenerate_recovery_ui",
                    outcome = "error",
                    error_class = e.reason_class(),
                    "lepton.totp.regenerate_recovery_ui"
                );
                map_enroll_err(e)
            })?;
        tracing::info!(
            operation = "totp_regenerate_recovery_ui",
            outcome = "ok",
            "lepton.totp.regenerate_recovery_ui"
        );
        Ok(codes)
    }
}
