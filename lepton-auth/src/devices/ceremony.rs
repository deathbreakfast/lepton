//! Persist short-lived `WebAuthn` ceremony state in Valence.

use chrono::{Duration, Utc};
use lepton_host_adapter::generated::{AuthDeviceCeremony, AuthDeviceCeremonyPhase, User};
use valence::{Model, RecordId, Valence};

use super::DeviceError;
use crate::security::random_token_part;

/// Ceremony TTL (challenge replay window).
pub(super) const CEREMONY_TTL_SECS: i64 = 300;

pub(super) fn bare_id(record: &RecordId) -> String {
    valence::extract_id_from_record(record).unwrap_or_else(|_| record.id().to_string())
}

pub(super) async fn ensure_user(valence: &Valence, user: &RecordId) -> Result<(), DeviceError> {
    let uid = bare_id(user);
    if User::get_used(&uid, valence, valence::use_!(r"In **trusted devices**, we **load User** so the application can decide what to do next in this workflow. The result is used by **trusted devices** logic—not necessarily displayed on a page unless that feature’s UI shows it."))
        .await
        .map_err(|_| DeviceError::Store)?
        .is_none()
    {
        return Err(DeviceError::UserMissing);
    }
    Ok(())
}

/// Insert a pending ceremony row; returns ceremony id.
pub(super) async fn insert_ceremony(
    valence: &Valence,
    user: &RecordId,
    phase: AuthDeviceCeremonyPhase,
    label: Option<String>,
    state_json: serde_json::Value,
) -> Result<String, DeviceError> {
    ensure_user(valence, user).await?;
    let now = Utc::now();
    let expires_at = now + Duration::seconds(CEREMONY_TTL_SECS);
    let ceremony_id = random_token_part(16);
    let row = AuthDeviceCeremony::new(user.clone(), phase, label, state_json, expires_at, now, now)
        .map_err(|_| DeviceError::Store)?;
    AuthDeviceCeremony::upsert_used(&ceremony_id, row, valence, valence::use_!(r"When **trusted devices** needs to persist work, we **save Auth Device Ceremony** so the next step in that feature can continue with the latest values. People and services allowed for **trusted devices** use this data for that workflow—not as a general export of unrelated personal fields."))
        .await
        .map_err(|_| DeviceError::Store)?;
    Ok(ceremony_id)
}

/// Load ceremony for `user` + `phase` if present and not expired.
pub(super) async fn load_valid_ceremony(
    valence: &Valence,
    user: &RecordId,
    ceremony_id: &str,
    phase: AuthDeviceCeremonyPhase,
) -> Result<AuthDeviceCeremony, DeviceError> {
    let ceremony = AuthDeviceCeremony::get_used(ceremony_id, valence, valence::use_!(r"In **trusted devices**, we **load Auth Device Ceremony** so the application can decide what to do next in this workflow. The result is used by **trusted devices** logic—not necessarily displayed on a page unless that feature’s UI shows it."))
        .await
        .map_err(|_| DeviceError::Store)?
        .ok_or(DeviceError::CeremonyInvalid)?;
    if bare_id(ceremony.user()) != bare_id(user) {
        return Err(DeviceError::CeremonyInvalid);
    }
    if *ceremony.phase() != phase {
        return Err(DeviceError::CeremonyInvalid);
    }
    if *ceremony.expires_at() < Utc::now() {
        return Err(DeviceError::CeremonyInvalid);
    }
    Ok(ceremony)
}

/// One-time consume: invalidate by expiring the row (no Valence delete dispatcher required).
pub(super) async fn consume_ceremony(
    valence: &Valence,
    user: &RecordId,
    ceremony_id: &str,
    phase: AuthDeviceCeremonyPhase,
) -> Result<AuthDeviceCeremony, DeviceError> {
    let ceremony = load_valid_ceremony(valence, user, ceremony_id, phase).await?;
    let past = Utc::now() - Duration::seconds(1);
    ceremony
        .clone()
        .get_mutable_used(valence, valence::use_!(r"In **devices**, we **update this data** so later steps see the latest values for this workflow. Callers allowed for **devices** use the updated data; this is not a public export of unrelated fields."))
        .set_expires_at(past)
        .map_err(|_| DeviceError::Store)?
        .set_updated_at(Utc::now())
        .map_err(|_| DeviceError::Store)?
        .commit()
        .await
        .map_err(|_| DeviceError::Store)?;
    Ok(ceremony)
}
