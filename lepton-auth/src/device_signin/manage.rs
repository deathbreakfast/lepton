//! Signed-in devices: list, rename, move to another service user, sign out.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use lepton_host_adapter::generated::{SignedInDevice, SignedInDeviceStatus};
use lepton_identity::service_users::ServiceUserId;
use valence::{Model, RecordId, Valence};

use super::approve::usable_service_user;
use super::emit::{emit, DeviceSigninOperation};
use super::{caller_user, owned_by, write_error, DeviceSigninError};
use crate::service_users::tokens::CREATE_LOCK;
use crate::service_users::{
    get_service_user, list_service_user_tokens, revoke_service_user_token, ServiceUserError,
};

const MAX_NAME: usize = 80;

/// A signed-in device with when it was last seen.
#[derive(Debug, Clone)]
pub struct DeviceListing {
    /// The stored device: name, client, where it asked from, when it signed in and until when,
    /// the service user it acts as, and its token id.
    pub device: SignedInDevice,
    /// The later of when it collected its token and when the token was last used.
    pub last_seen_at: Option<DateTime<Utc>>,
}

/// Devices signed in as one service user, oldest first, for its page.
///
/// The owner and manage-any users may list them.
///
/// # Errors
///
/// [`DeviceSigninError::NotAUser`], [`DeviceSigninError::NotFound`] when the service user is
/// unknown to the caller, or [`DeviceSigninError::Store`].
pub async fn list_service_user_devices(
    valence: &Valence,
    service_user: &ServiceUserId,
) -> Result<Vec<DeviceListing>, DeviceSigninError> {
    caller_user(valence)?;
    get_service_user(valence, service_user).await?;
    let devices = SignedInDevice::get_from_service_user_id(
        service_user.as_str(),
        valence,
        valence::use_!(r"On a **service user's page**, we **list the devices signed in as it** with their name, app, where they asked from, when they signed in, when they were last seen and until when, so the owner can rename, move or sign them out."),
    )
    .await
    .map_err(|_| DeviceSigninError::Store)?;
    with_last_seen(valence, devices).await
}

/// The caller's own signed-in devices, oldest first, for Settings, Devices.
///
/// # Errors
///
/// [`DeviceSigninError::NotAUser`] or [`DeviceSigninError::Store`].
pub async fn list_my_devices(valence: &Valence) -> Result<Vec<DeviceListing>, DeviceSigninError> {
    let caller = caller_user(valence)?;
    let devices = SignedInDevice::get_from_user_id(
        &caller,
        valence,
        valence::use_!(r"On your **Devices** page, we **list the devices you signed in** with their name, app, the service user each acts as, where they asked from, when they signed in, when they were last seen and until when, so you can rename, move or sign them out."),
    )
    .await
    .map_err(|_| DeviceSigninError::Store)?;
    with_last_seen(valence, devices).await
}

/// Pair each device with when it was last seen, from its token's last use.
async fn with_last_seen(
    valence: &Valence,
    mut devices: Vec<SignedInDevice>,
) -> Result<Vec<DeviceListing>, DeviceSigninError> {
    devices.sort_by_key(|d| *d.signed_in_at());
    let mut token_use: HashMap<String, DateTime<Utc>> = HashMap::new();
    let mut seen_service_users: Vec<String> = Vec::new();
    for device in &devices {
        let Some(id) = device.service_user().map(|rid| rid.id().to_string()) else {
            continue;
        };
        if seen_service_users.contains(&id) {
            continue;
        }
        seen_service_users.push(id.clone());
        let Ok(service_user) = ServiceUserId::parse(&id) else {
            continue;
        };
        let tokens = match list_service_user_tokens(valence, &service_user).await {
            Ok(tokens) => tokens,
            // A service user being deleted takes its devices with it; show what's left.
            Err(ServiceUserError::NotFound) => continue,
            Err(e) => return Err(e.into()),
        };
        for token in tokens {
            if let (Some(rid), Some(used)) = (token.id(), token.last_used_at()) {
                token_use.insert(rid.id().to_string(), *used);
            }
        }
    }
    Ok(devices
        .into_iter()
        .map(|device| {
            let used = device.token().and_then(|t| token_use.get(t)).copied();
            let last_seen_at = match (device.last_seen_at().copied(), used) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            };
            DeviceListing {
                device,
                last_seen_at,
            }
        })
        .collect())
}

async fn load_device(valence: &Valence, id: &str) -> Result<SignedInDevice, DeviceSigninError> {
    SignedInDevice::get(
        id,
        valence,
        valence::use_!(r"When you **rename, move or sign out a device**, we **load the device** to check that it is yours and to change it."),
    )
    .await
    .map_err(|e| match e {
        valence::Error::PendingDeletion(_) => DeviceSigninError::NotFound,
        _ => DeviceSigninError::Store,
    })?
    .ok_or(DeviceSigninError::NotFound)
}

async fn load_owned_device(
    valence: &Valence,
    caller: &str,
    id: &str,
) -> Result<SignedInDevice, DeviceSigninError> {
    let device = load_device(valence, id).await?;
    if !owned_by(device.user(), caller) {
        return Err(DeviceSigninError::Forbidden);
    }
    Ok(device)
}

/// Rename a device the caller owns (1-80 characters). The app and platform it reported stay.
///
/// # Errors
///
/// [`DeviceSigninError::NotAUser`]; [`DeviceSigninError::InvalidInput`] for a bad name;
/// [`DeviceSigninError::NotFound`]; [`DeviceSigninError::Forbidden`] for someone else's device;
/// [`DeviceSigninError::Store`].
pub async fn rename_device(
    valence: &Valence,
    device_id: &str,
    name: &str,
) -> Result<SignedInDevice, DeviceSigninError> {
    let result = rename_inner(valence, device_id, name).await;
    emit(
        DeviceSigninOperation::Rename,
        result.as_ref().err().map(DeviceSigninError::reason_class),
    );
    result
}

async fn rename_inner(
    valence: &Valence,
    device_id: &str,
    name: &str,
) -> Result<SignedInDevice, DeviceSigninError> {
    let caller = caller_user(valence)?;
    let name = name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME {
        return Err(DeviceSigninError::InvalidInput { field: "name" });
    }
    let device = load_owned_device(valence, &caller, device_id).await?;
    device
        .get_mutable(
            valence,
            valence::use_!(r"When you **rename a device**, we **save its new name**, which you see on the service user's page and under Settings, Devices."),
        )
        .set_name(name.to_string())
        .map_err(|_| DeviceSigninError::InvalidInput { field: "name" })?
        .commit()
        .await
        .map_err(|e| write_error(&e))
}

/// Move a device to another service user the caller owns, after a recent step-up.
///
/// The device stays signed in. Its old token is revoked at once, and it collects a new one, with
/// the same scopes and lifetime, the next time it polls with its device code.
///
/// # Errors
///
/// - [`DeviceSigninError::StepUp`] when the session has no recent step-up.
/// - [`DeviceSigninError::NotAUser`]; [`DeviceSigninError::NotFound`] for an unknown device or
///   service user.
/// - [`DeviceSigninError::Forbidden`] when the device or the target service user is someone
///   else's.
/// - [`DeviceSigninError::InvalidInput`] when the device already acts as that service user.
/// - [`DeviceSigninError::Paused`] / [`DeviceSigninError::QuotaReached`] for a target that
///   can't take it.
/// - [`DeviceSigninError::Store`].
#[cfg(feature = "totp")]
pub async fn move_device(
    valence: &Valence,
    device_id: &str,
    to: &ServiceUserId,
) -> Result<SignedInDevice, DeviceSigninError> {
    use crate::step_up::{require_recent_verification, StepUpScope};

    if let Err(e) = require_recent_verification(StepUpScope::SensitiveMutation).await {
        let err = DeviceSigninError::from_step_up(&e);
        emit(DeviceSigninOperation::Move, Some(err.reason_class()));
        return Err(err);
    }
    move_after_step_up(valence, device_id, to).await
}

/// **Test only.** [`move_device`] without the step-up check.
///
/// # Errors
///
/// As [`move_device`], except [`DeviceSigninError::StepUp`].
#[cfg(feature = "test-utils")]
pub async fn move_device_without_step_up(
    valence: &Valence,
    device_id: &str,
    to: &ServiceUserId,
) -> Result<SignedInDevice, DeviceSigninError> {
    move_after_step_up(valence, device_id, to).await
}

#[cfg_attr(not(any(feature = "totp", feature = "test-utils")), allow(dead_code))]
async fn move_after_step_up(
    valence: &Valence,
    device_id: &str,
    to: &ServiceUserId,
) -> Result<SignedInDevice, DeviceSigninError> {
    let result = move_inner(valence, device_id, to).await;
    emit(
        DeviceSigninOperation::Move,
        result.as_ref().err().map(DeviceSigninError::reason_class),
    );
    result
}

async fn move_inner(
    valence: &Valence,
    device_id: &str,
    to: &ServiceUserId,
) -> Result<SignedInDevice, DeviceSigninError> {
    let caller = caller_user(valence)?;
    let device = load_owned_device(valence, &caller, device_id).await?;
    let target = get_service_user(valence, to).await?;
    let current = device.service_user().map(|rid| rid.id().to_string());
    if current.as_deref() == Some(to.as_str()) {
        return Err(DeviceSigninError::InvalidInput {
            field: "service_user",
        });
    }

    let _guard = CREATE_LOCK.lock().await;
    usable_service_user(valence, &caller, &target).await?;
    revoke_device_token(valence, &device).await?;
    let moved = device
        .get_mutable(
            valence,
            valence::use_!(r"When you **move a device to another service user**, we **record the service user it now acts as** and that it is waiting for a new token, so its old token stops working and the device collects a new one the next time it checks in."),
        )
        .set_service_user(RecordId::new("service_user_account", to.as_str()))
        .and_then(|m| m.set_status(SignedInDeviceStatus::IssuePending))
        .map_err(|_| DeviceSigninError::Store)?
        .clear_token()
        .clear_signed_in_until()
        .commit()
        .await
        .map_err(|e| write_error(&e))?;
    tracing::info!(
        target: "lepton.device_signin",
        op = "move",
        service_user_id = to.as_str(),
        "device moved"
    );
    Ok(moved)
}

/// Sign a device out: revoke its token and delete the device.
///
/// The owner and manage-any users may sign a device out.
///
/// # Errors
///
/// [`DeviceSigninError::NotAUser`], [`DeviceSigninError::NotFound`],
/// [`DeviceSigninError::Forbidden`], or [`DeviceSigninError::Store`].
pub async fn sign_out_device(valence: &Valence, device_id: &str) -> Result<(), DeviceSigninError> {
    let result = sign_out_inner(valence, device_id).await;
    emit(
        DeviceSigninOperation::SignOut,
        result.as_ref().err().map(DeviceSigninError::reason_class),
    );
    result
}

async fn sign_out_inner(valence: &Valence, device_id: &str) -> Result<(), DeviceSigninError> {
    caller_user(valence)?;
    let device = load_device(valence, device_id).await?;
    revoke_device_token(valence, &device).await?;
    SignedInDevice::delete(
        device_id,
        valence,
        valence::use_!(r"When a **device is signed out**, we **delete the device** with its name, app, address and code, so it can't collect another token and none of it stays behind."),
    )
    .await
    .map_err(|e| write_error(&e))?;
    tracing::info!(target: "lepton.device_signin", op = "sign_out", "device signed out");
    Ok(())
}

/// Revoke the device's current token, if it has one.
async fn revoke_device_token(
    valence: &Valence,
    device: &SignedInDevice,
) -> Result<(), DeviceSigninError> {
    let (Some(token), Some(service_user)) = (
        device.token(),
        device
            .service_user()
            .and_then(|rid| ServiceUserId::parse(rid.id()).ok()),
    ) else {
        return Ok(());
    };
    match revoke_service_user_token(valence, &service_user, token).await {
        // Gone with its service user already: nothing left to stop.
        Ok(_) | Err(ServiceUserError::NotFound) => Ok(()),
        Err(e) => Err(e.into()),
    }
}
