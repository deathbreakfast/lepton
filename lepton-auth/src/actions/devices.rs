//! Server functions for trusted devices / passkeys (Account Settings).

use leptos::prelude::*;

#[cfg(feature = "ssr")]
#[allow(clippy::needless_pass_by_value)] // maps owned DeviceError from Result paths
fn map_device_err(err: crate::devices::DeviceError) -> ServerFnError {
    ServerFnError::new(err.to_string())
}

/// Session-actor Valence for device CUD; owner policies on `AuthDevice` and
/// `AuthDeviceCeremony` scope every row to `auth_user.id`.
#[cfg(feature = "ssr")]
async fn device_valence(
) -> Result<(higgs::Higgs, lepton_host_adapter::User, valence::Valence), ServerFnError> {
    let (ctx, auth_user) = crate::ssr_support::require_auth_user().await?;
    let valence = crate::ssr_support::user_valence(&ctx)?;
    Ok((ctx, auth_user, valence))
}

/// List the signed-in user's auth devices (no secret material).
#[server(ListMyAuthDevices)]
pub async fn list_my_auth_devices() -> Result<Vec<crate::devices::AuthDeviceView>, ServerFnError> {
    let (_ctx, auth_user, valence) = device_valence().await?;
    tracing::info!(
        operation = "device_list",
        outcome = "start",
        "lepton_auth.devices.list"
    );
    let devices = crate::devices::list_auth_devices(&valence, &auth_user.id)
        .await
        .map_err(|e| {
            tracing::warn!(
                operation = "device_list",
                outcome = "error",
                reason_class = e.reason_class(),
                "lepton_auth.devices.list"
            );
            map_device_err(e)
        })?;
    tracing::info!(
        operation = "device_list",
        outcome = "ok",
        "lepton_auth.devices.list"
    );
    Ok(devices)
}

/// Start TrustedBrowser registration; returns device id + one-time confirm code.
#[server(RegisterTrustedBrowser)]
pub async fn register_trusted_browser(
    /// Operator-facing label (e.g. "This laptop").
    label: String,
) -> Result<crate::devices::PendingAuthDevice, ServerFnError> {
    let (_ctx, auth_user, valence) = device_valence().await?;
    tracing::info!(
        operation = "trusted_browser_register",
        outcome = "start",
        "lepton_auth.devices.register_trusted_browser"
    );
    crate::devices::register_auth_device(
        &valence,
        &auth_user.id,
        crate::devices::AuthDeviceKind::TrustedBrowser,
        label.trim(),
    )
    .await
    .map_err(|e| {
        tracing::warn!(
            operation = "trusted_browser_register",
            outcome = "error",
            reason_class = e.reason_class(),
            "lepton_auth.devices.register_trusted_browser"
        );
        map_device_err(e)
    })
    .inspect(|_| {
        tracing::info!(
            operation = "trusted_browser_register",
            outcome = "ok",
            "lepton_auth.devices.register_trusted_browser"
        );
    })
}

/// Confirm a pending TrustedBrowser device with the one-time code.
#[server(ConfirmTrustedBrowser)]
pub async fn confirm_trusted_browser(
    /// Pending device id from [`register_trusted_browser`].
    device_id: String,
    /// One-time confirm code (never logged).
    confirm_code: String,
) -> Result<(), ServerFnError> {
    let (_ctx, auth_user, valence) = device_valence().await?;
    tracing::info!(
        operation = "trusted_browser_confirm",
        outcome = "start",
        "lepton_auth.devices.confirm_trusted_browser"
    );
    crate::devices::confirm_auth_device(
        &valence,
        &auth_user.id,
        device_id.trim(),
        confirm_code.trim(),
    )
    .await
    .map_err(|e| {
        tracing::warn!(
            operation = "trusted_browser_confirm",
            outcome = "error",
            reason_class = e.reason_class(),
            "lepton_auth.devices.confirm_trusted_browser"
        );
        map_device_err(e)
    })?;
    tracing::info!(
        operation = "trusted_browser_confirm",
        outcome = "ok",
        "lepton_auth.devices.confirm_trusted_browser"
    );
    Ok(())
}

/// Soft-revoke one of the signed-in user's auth devices.
#[server(RevokeMyAuthDevice)]
pub async fn revoke_my_auth_device(
    /// Device id to revoke.
    device_id: String,
) -> Result<(), ServerFnError> {
    let (_ctx, auth_user, valence) = device_valence().await?;
    tracing::info!(
        operation = "device_revoke",
        outcome = "start",
        "lepton_auth.devices.revoke"
    );
    crate::devices::revoke_auth_device(&valence, &auth_user.id, device_id.trim())
        .await
        .map_err(|e| {
            tracing::warn!(
                operation = "device_revoke",
                outcome = "error",
                reason_class = e.reason_class(),
                "lepton_auth.devices.revoke"
            );
            map_device_err(e)
        })?;
    tracing::info!(
        operation = "device_revoke",
        outcome = "ok",
        "lepton_auth.devices.revoke"
    );
    Ok(())
}

/// Begin `WebAuthn` passkey registration (creation options for the browser).
#[server(BeginPasskeyRegistration)]
#[allow(clippy::unused_async)] // `#[server]` must be async; body awaits only with `webauthn`
pub async fn begin_passkey_registration(
    /// Operator-facing label for the new passkey.
    label: String,
) -> Result<crate::devices::PendingWebauthnRegistration, ServerFnError> {
    #[cfg(not(feature = "webauthn"))]
    {
        let _ = label;
        Err(map_device_err(crate::devices::DeviceError::UnsupportedKind))
    }
    #[cfg(feature = "webauthn")]
    {
        let (_ctx, auth_user, valence) = device_valence().await?;
        let services =
            crate::services::auth_services().map_err(|e| ServerFnError::new(e.to_string()))?;
        let rp = services.require_webauthn_rp().map_err(map_device_err)?;
        tracing::info!(
            operation = "webauthn_begin_registration",
            outcome = "start",
            "lepton_auth.devices.webauthn_begin_registration"
        );
        crate::devices::begin_webauthn_registration(&valence, rp, &auth_user.id, label.trim())
            .await
            .map_err(|e| {
                tracing::warn!(
                    operation = "webauthn_begin_registration",
                    outcome = "error",
                    reason_class = e.reason_class(),
                    "lepton_auth.devices.webauthn_begin_registration"
                );
                map_device_err(e)
            })
            .inspect(|_| {
                tracing::info!(
                    operation = "webauthn_begin_registration",
                    outcome = "ok",
                    "lepton_auth.devices.webauthn_begin_registration"
                );
            })
    }
}

/// Finish `WebAuthn` passkey registration with attestation JSON from the browser.
#[server(FinishPasskeyRegistration)]
#[allow(clippy::unused_async)] // `#[server]` must be async; body awaits only with `webauthn`
pub async fn finish_passkey_registration(
    /// Ceremony id from [`begin_passkey_registration`].
    ceremony_id: String,
    /// Attestation JSON from `navigator.credentials.create` (not logged).
    attestation_json: String,
) -> Result<crate::devices::RegisteredWebauthnDevice, ServerFnError> {
    #[cfg(not(feature = "webauthn"))]
    {
        let _ = (ceremony_id, attestation_json);
        Err(map_device_err(crate::devices::DeviceError::UnsupportedKind))
    }
    #[cfg(feature = "webauthn")]
    {
        let (_ctx, auth_user, valence) = device_valence().await?;
        let services =
            crate::services::auth_services().map_err(|e| ServerFnError::new(e.to_string()))?;
        let rp = services.require_webauthn_rp().map_err(map_device_err)?;
        let attestation: serde_json::Value = serde_json::from_str(attestation_json.trim())
            .map_err(|_| map_device_err(crate::devices::DeviceError::WebauthnVerifyFailed))?;
        tracing::info!(
            operation = "webauthn_finish_registration",
            outcome = "start",
            "lepton_auth.devices.webauthn_finish_registration"
        );
        crate::devices::finish_webauthn_registration(
            &valence,
            rp,
            &auth_user.id,
            ceremony_id.trim(),
            &attestation,
        )
        .await
        .map_err(|e| {
            tracing::warn!(
                operation = "webauthn_finish_registration",
                outcome = "error",
                reason_class = e.reason_class(),
                "lepton_auth.devices.webauthn_finish_registration"
            );
            map_device_err(e)
        })
        .inspect(|_| {
            tracing::info!(
                operation = "webauthn_finish_registration",
                outcome = "ok",
                "lepton_auth.devices.webauthn_finish_registration"
            );
        })
    }
}

/// Begin `WebAuthn` assertion (verify an enrolled passkey).
#[server(BeginPasskeyAssertion)]
#[allow(clippy::unused_async)] // `#[server]` must be async; body awaits only with `webauthn`
pub async fn begin_passkey_assertion(
) -> Result<crate::devices::PendingWebauthnAssertion, ServerFnError> {
    #[cfg(not(feature = "webauthn"))]
    {
        Err(map_device_err(crate::devices::DeviceError::UnsupportedKind))
    }
    #[cfg(feature = "webauthn")]
    {
        let (_ctx, auth_user, valence) = device_valence().await?;
        let services =
            crate::services::auth_services().map_err(|e| ServerFnError::new(e.to_string()))?;
        let rp = services.require_webauthn_rp().map_err(map_device_err)?;
        tracing::info!(
            operation = "webauthn_begin_assertion",
            outcome = "start",
            "lepton_auth.devices.webauthn_begin_assertion"
        );
        crate::devices::begin_webauthn_assertion(&valence, rp, &auth_user.id)
            .await
            .map_err(|e| {
                tracing::warn!(
                    operation = "webauthn_begin_assertion",
                    outcome = "error",
                    reason_class = e.reason_class(),
                    "lepton_auth.devices.webauthn_begin_assertion"
                );
                map_device_err(e)
            })
            .inspect(|_| {
                tracing::info!(
                    operation = "webauthn_begin_assertion",
                    outcome = "ok",
                    "lepton_auth.devices.webauthn_begin_assertion"
                );
            })
    }
}

/// Finish `WebAuthn` assertion with assertion JSON from the browser.
#[server(FinishPasskeyAssertion)]
#[allow(clippy::unused_async)] // `#[server]` must be async; body awaits only with `webauthn`
pub async fn finish_passkey_assertion(
    /// Ceremony id from [`begin_passkey_assertion`].
    ceremony_id: String,
    /// Assertion JSON from `navigator.credentials.get` (not logged).
    assertion_json: String,
) -> Result<crate::devices::AuthDeviceView, ServerFnError> {
    #[cfg(not(feature = "webauthn"))]
    {
        let _ = (ceremony_id, assertion_json);
        Err(map_device_err(crate::devices::DeviceError::UnsupportedKind))
    }
    #[cfg(feature = "webauthn")]
    {
        let (_ctx, auth_user, valence) = device_valence().await?;
        let services =
            crate::services::auth_services().map_err(|e| ServerFnError::new(e.to_string()))?;
        let rp = services.require_webauthn_rp().map_err(map_device_err)?;
        let assertion: serde_json::Value = serde_json::from_str(assertion_json.trim())
            .map_err(|_| map_device_err(crate::devices::DeviceError::WebauthnVerifyFailed))?;
        tracing::info!(
            operation = "webauthn_finish_assertion",
            outcome = "start",
            "lepton_auth.devices.webauthn_finish_assertion"
        );
        let view = crate::devices::finish_webauthn_assertion(
            &valence,
            rp,
            &auth_user.id,
            ceremony_id.trim(),
            &assertion,
        )
        .await
        .map_err(|e| {
            tracing::warn!(
                operation = "webauthn_finish_assertion",
                outcome = "error",
                reason_class = e.reason_class(),
                "lepton_auth.devices.webauthn_finish_assertion"
            );
            map_device_err(e)
        })?;
        tracing::info!(
            operation = "webauthn_finish_assertion",
            outcome = "ok",
            "lepton_auth.devices.webauthn_finish_assertion"
        );
        Ok(view)
    }
}
