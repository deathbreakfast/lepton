//! `TrustedBrowser` long-lived binding cookie (MFA-skip proof).

use chrono::Utc;
use lepton_host_adapter::auth::hash_password;
use lepton_host_adapter::generated::{AuthDevice, AuthDeviceKind as GeneratedKind};
use valence::{Model, RecordId, Valence};

use super::DeviceError;
use crate::security::random_token_part;

fn bare_id(record: &RecordId) -> String {
    valence::extract_id_from_record(record).unwrap_or_else(|_| record.id().to_string())
}

/// `HttpOnly` cookie name for `TrustedBrowser` MFA-skip binding.
pub const DEVICE_BINDING_COOKIE: &str = "lepton_device";

/// Parsed `device_id.secret` binding cookie value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceBindingCookie {
    /// Auth device id.
    pub device_id: String,
    /// Raw binding secret (never logged).
    pub secret: String,
}

impl DeviceBindingCookie {
    /// Parse `device_id.secret` (first `.` splits id from secret).
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        let (device_id, secret) = raw.split_once('.')?;
        if device_id.is_empty() || secret.is_empty() {
            return None;
        }
        Some(Self {
            device_id: device_id.to_string(),
            secret: secret.to_string(),
        })
    }

    /// Wire form for Set-Cookie.
    #[must_use]
    pub fn encode(&self) -> String {
        format!("{}.{}", self.device_id, self.secret)
    }
}

/// Mint a long-lived binding secret for a trusted, non-revoked `TrustedBrowser` device.
///
/// Returns the cookie value to set on the response. Stores Argon2 hash on the device.
///
/// # Errors
///
/// Missing / revoked / pending / wrong kind / store.
pub async fn issue_device_binding(
    valence: &Valence,
    user: &RecordId,
    device_id: &str,
) -> Result<DeviceBindingCookie, DeviceError> {
    let device = AuthDevice::get(device_id, valence, valence::use_!(r"In **trusted devices**, we **load Auth Device** so the application can decide what to do next in this workflow. The result is used by **trusted devices** logic—not necessarily displayed on a page unless that feature’s UI shows it."))
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
    if *device.kind() != GeneratedKind::TrustedBrowser {
        return Err(DeviceError::UnsupportedKind);
    }
    let secret = random_token_part(24);
    let hash = hash_password(&secret).map_err(|_| DeviceError::Store)?;
    let now = Utc::now();
    device
        .get_mutable(valence, valence::use_!(r"In **devices**, we **update this data** so later steps see the latest values for this workflow. Callers allowed for **devices** use the updated data; this is not a public export of unrelated fields."))
        .set_binding_secret_hash(hash)
        .map_err(|_| DeviceError::Store)?
        .set_last_seen_at(now)
        .map_err(|_| DeviceError::Store)?
        .set_updated_at(now)
        .map_err(|_| DeviceError::Store)?
        .commit()
        .await
        .map_err(|_| DeviceError::Store)?;
    Ok(DeviceBindingCookie {
        device_id: device_id.to_string(),
        secret,
    })
}

/// Verify a `TrustedBrowser` binding cookie against the stored hash.
///
/// On success touches `last_seen_at` and returns the device id.
///
/// # Errors
///
/// Invalid cookie / revoked / mismatch / store.
pub async fn verify_device_binding(
    valence: &Valence,
    user: &RecordId,
    cookie: &DeviceBindingCookie,
) -> Result<String, DeviceError> {
    use argon2::{password_hash::PasswordHash, PasswordVerifier};

    let device = AuthDevice::get(&cookie.device_id, valence, valence::use_!(r"In **trusted devices**, we **load Auth Device** so the application can decide what to do next in this workflow. The result is used by **trusted devices** logic—not necessarily displayed on a page unless that feature’s UI shows it."))
        .await
        .map_err(|_| DeviceError::Store)?
        .ok_or(DeviceError::BindingInvalid)?;
    if bare_id(device.user()) != bare_id(user) {
        return Err(DeviceError::BindingInvalid);
    }
    if device.revoked_at().is_some() {
        return Err(DeviceError::Revoked);
    }
    if device.trusted_at().is_none() {
        return Err(DeviceError::BindingInvalid);
    }
    if *device.kind() != GeneratedKind::TrustedBrowser {
        return Err(DeviceError::BindingInvalid);
    }
    let Some(hash) = device.binding_secret_hash() else {
        return Err(DeviceError::BindingInvalid);
    };
    let parsed = PasswordHash::new(hash).map_err(|_| DeviceError::Store)?;
    if argon2::Argon2::default()
        .verify_password(cookie.secret.as_bytes(), &parsed)
        .is_err()
    {
        return Err(DeviceError::BindingInvalid);
    }
    let now = Utc::now();
    device
        .get_mutable(valence, valence::use_!(r"In **devices**, we **update this data** so later steps see the latest values for this workflow. Callers allowed for **devices** use the updated data; this is not a public export of unrelated fields."))
        .set_last_seen_at(now)
        .map_err(|_| DeviceError::Store)?
        .set_updated_at(now)
        .map_err(|_| DeviceError::Store)?
        .commit()
        .await
        .map_err(|_| DeviceError::Store)?;
    Ok(cookie.device_id.clone())
}

/// Register + confirm a `TrustedBrowser` and immediately issue a binding cookie.
///
/// Used after MFA when the user chooses “remember this browser”.
///
/// # Errors
///
/// Propagates register / confirm / issue failures.
pub async fn register_and_bind_trusted_browser(
    valence: &Valence,
    user: &RecordId,
    label: &str,
) -> Result<DeviceBindingCookie, DeviceError> {
    use super::api::{confirm_auth_device, register_auth_device};
    use super::types::AuthDeviceKind;

    let pending =
        register_auth_device(valence, user, AuthDeviceKind::TrustedBrowser, label).await?;
    confirm_auth_device(valence, user, &pending.device_id, &pending.confirm_code).await?;
    issue_device_binding(valence, user, &pending.device_id).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_binding_cookie_parse_happy() {
        let c = DeviceBindingCookie::parse("dev123.secrethere").expect("parse");
        assert_eq!(c.device_id, "dev123");
        assert_eq!(c.secret, "secrethere");
        assert_eq!(c.encode(), "dev123.secrethere");
    }

    #[test]
    fn device_binding_cookie_parse_sad() {
        assert!(DeviceBindingCookie::parse("").is_none());
        assert!(DeviceBindingCookie::parse("nosecret").is_none());
        assert!(DeviceBindingCookie::parse(".onlysecret").is_none());
        assert!(DeviceBindingCookie::parse("onlyid.").is_none());
    }
}
