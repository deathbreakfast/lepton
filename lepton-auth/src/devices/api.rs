//! Auth device register / confirm / list / revoke.

use chrono::Utc;
use lepton_host_adapter::auth::hash_password;
use lepton_host_adapter::generated::{AuthDevice, AuthDeviceKind as GeneratedKind, User};
use valence::{Model, RecordId, Valence};

use super::types::{AuthDeviceKind, AuthDeviceView, PendingAuthDevice};
use super::DeviceError;
use crate::security::random_token_part;

fn bare_id(record: &RecordId) -> String {
    valence::extract_id_from_record(record).unwrap_or_else(|_| record.id().to_string())
}

const fn kind_to_generated(kind: AuthDeviceKind) -> Result<GeneratedKind, DeviceError> {
    match kind {
        AuthDeviceKind::TrustedBrowser => Ok(GeneratedKind::TrustedBrowser),
        AuthDeviceKind::WebAuthn => Err(DeviceError::UnsupportedKind),
    }
}

/// Register a pending [`AuthDeviceKind::TrustedBrowser`] device.
///
/// # Errors
///
/// [`DeviceError::UnsupportedKind`] for [`AuthDeviceKind::WebAuthn`]; store/user otherwise.
pub async fn register_auth_device(
    valence: &Valence,
    user: &RecordId,
    kind: AuthDeviceKind,
    label: &str,
) -> Result<PendingAuthDevice, DeviceError> {
    let gen_kind = kind_to_generated(kind)?;
    let uid = bare_id(user);
    if User::get_used(&uid, valence, valence::use_!("get User in src/devices/api.rs; Valence persistence for this feature path; typed store; visible to session actor / service path."))
        .await
        .map_err(|_| DeviceError::Store)?
        .is_none()
    {
        return Err(DeviceError::UserMissing);
    }
    let confirm_code = random_token_part(8);
    let confirm_hash = hash_password(&confirm_code).map_err(|_| DeviceError::Store)?;
    let now = Utc::now();
    let device_id = random_token_part(12);
    let row = AuthDevice::new(
        user.clone(),
        gen_kind,
        label.trim().to_string(),
        Some(confirm_hash),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        now,
        now,
    )
    .map_err(|_| DeviceError::Store)?;
    AuthDevice::upsert_used(&device_id, row, valence, valence::use_!("upsert AuthDevice in src/devices/api.rs; Valence persistence for this feature path; typed store; visible to session actor / service path."))
        .await
        .map_err(|_| DeviceError::Store)?;
    #[cfg(feature = "spectra")]
    crate::spectra_emit::device(
        match kind {
            AuthDeviceKind::TrustedBrowser => crate::spectra_emit::DeviceKind::TrustedBrowser,
            AuthDeviceKind::WebAuthn => crate::spectra_emit::DeviceKind::Webauthn,
        },
        crate::spectra_emit::DeviceOperation::Register,
        crate::spectra_emit::AuthOutcome::Success,
        "none",
    );
    Ok(PendingAuthDevice {
        device_id,
        confirm_code,
    })
}

/// Confirm a pending device with the one-time code.
///
/// # Errors
///
/// Mismatch / revoked / store.
pub async fn confirm_auth_device(
    valence: &Valence,
    user: &RecordId,
    device_id: &str,
    confirm_code: &str,
) -> Result<(), DeviceError> {
    use argon2::{password_hash::PasswordHash, PasswordVerifier};

    let device = AuthDevice::get_used(device_id, valence, valence::use_!("get AuthDevice in src/devices/api.rs; Valence persistence for this feature path; typed store; visible to session actor / service path."))
        .await
        .map_err(|_| DeviceError::Store)?
        .ok_or(DeviceError::DeviceMissing)?;
    if bare_id(device.user()) != bare_id(user) {
        return Err(DeviceError::DeviceMissing);
    }
    if device.revoked_at().is_some() {
        return Err(DeviceError::Revoked);
    }
    if device.trusted_at().is_some() {
        return Ok(());
    }
    let Some(hash) = device.confirm_secret_hash() else {
        return Err(DeviceError::Pending);
    };
    let parsed = PasswordHash::new(hash).map_err(|_| DeviceError::Store)?;
    if argon2::Argon2::default()
        .verify_password(confirm_code.trim().as_bytes(), &parsed)
        .is_err()
    {
        return Err(DeviceError::Mismatch);
    }
    let now = Utc::now();
    device
        .get_mutable_used(valence, valence::use_!("get_mutable via api.rs; mutable handle for in-place update; typed store; session/service path."))
        .set_trusted_at(now)
        .map_err(|_| DeviceError::Store)?
        .set_last_seen_at(now)
        .map_err(|_| DeviceError::Store)?
        .set_updated_at(now)
        .map_err(|_| DeviceError::Store)?
        .commit()
        .await
        .map_err(|_| DeviceError::Store)?;
    #[cfg(feature = "spectra")]
    crate::spectra_emit::device(
        crate::spectra_emit::DeviceKind::TrustedBrowser,
        crate::spectra_emit::DeviceOperation::Confirm,
        crate::spectra_emit::AuthOutcome::Success,
        "none",
    );
    Ok(())
}

/// List devices for `user` (no secret material).
///
/// # Errors
///
/// Store failures.
pub async fn list_auth_devices(
    valence: &Valence,
    user: &RecordId,
) -> Result<Vec<AuthDeviceView>, DeviceError> {
    let uid = bare_id(user);
    let rows = AuthDevice::get_from_user_id(&uid, valence)
        .await
        .map_err(|_| DeviceError::Store)?;
    Ok(rows
        .into_iter()
        .filter_map(|d| {
            let id = d.id().map(bare_id)?;
            let kind = match d.kind() {
                GeneratedKind::TrustedBrowser => AuthDeviceKind::TrustedBrowser,
                GeneratedKind::Webauthn => AuthDeviceKind::WebAuthn,
            };
            Some(AuthDeviceView {
                id,
                kind,
                label: d.label().clone(),
                credential_id: d.credential_id().cloned(),
                sign_count: d.sign_count().copied(),
                trusted_at: d.trusted_at().copied(),
                last_seen_at: d.last_seen_at().copied(),
                revoked_at: d.revoked_at().copied(),
            })
        })
        .collect())
}

/// Revoke a device.
///
/// # Errors
///
/// Missing / store.
pub async fn revoke_auth_device(
    valence: &Valence,
    user: &RecordId,
    device_id: &str,
) -> Result<(), DeviceError> {
    let device = AuthDevice::get_used(device_id, valence, valence::use_!("get AuthDevice in src/devices/api.rs; Valence persistence for this feature path; typed store; visible to session actor / service path."))
        .await
        .map_err(|_| DeviceError::Store)?
        .ok_or(DeviceError::DeviceMissing)?;
    if bare_id(device.user()) != bare_id(user) {
        return Err(DeviceError::DeviceMissing);
    }
    let now = Utc::now();
    device
        .get_mutable_used(valence, valence::use_!("get_mutable via api.rs; mutable handle for in-place update; typed store; session/service path."))
        .set_revoked_at(now)
        .map_err(|_| DeviceError::Store)?
        .clear_binding_secret_hash()
        .set_updated_at(now)
        .map_err(|_| DeviceError::Store)?
        .commit()
        .await
        .map_err(|_| DeviceError::Store)?;
    #[cfg(feature = "spectra")]
    crate::spectra_emit::device(
        crate::spectra_emit::DeviceKind::TrustedBrowser,
        crate::spectra_emit::DeviceOperation::Revoke,
        crate::spectra_emit::AuthOutcome::Success,
        "none",
    );
    Ok(())
}

/// Touch `last_seen_at` on a trusted, non-revoked device.
///
/// # Errors
///
/// Pending / revoked / missing / store.
pub async fn touch_auth_device(
    valence: &Valence,
    user: &RecordId,
    device_id: &str,
) -> Result<(), DeviceError> {
    let device = AuthDevice::get_used(device_id, valence, valence::use_!("get AuthDevice in src/devices/api.rs; Valence persistence for this feature path; typed store; visible to session actor / service path."))
        .await
        .map_err(|_| DeviceError::Store)?
        .ok_or(DeviceError::DeviceMissing)?;
    if bare_id(device.user()) != bare_id(user) {
        return Err(DeviceError::DeviceMissing);
    }
    if device.revoked_at().is_some() {
        return Err(DeviceError::Revoked);
    }
    if device.trusted_at().is_none() {
        return Err(DeviceError::Pending);
    }
    let now = Utc::now();
    device
        .get_mutable_used(valence, valence::use_!("get_mutable via api.rs; mutable handle for in-place update; typed store; session/service path."))
        .set_last_seen_at(now)
        .map_err(|_| DeviceError::Store)?
        .set_updated_at(now)
        .map_err(|_| DeviceError::Store)?
        .commit()
        .await
        .map_err(|_| DeviceError::Store)?;
    Ok(())
}
