//! `WebAuthn` registration and assertion for [`AuthDeviceKind::WebAuthn`].

use chrono::Utc;
use lepton_host_adapter::generated::{
    AuthDevice, AuthDeviceCeremonyPhase, AuthDeviceKind as GeneratedKind,
};
use serde_json::Value;
use valence::{Model, RecordId, Valence};
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential,
};

use super::ceremony::{bare_id, consume_ceremony, insert_ceremony};
use super::rp::WebauthnRpConfig;
use super::types::{
    AuthDeviceKind, AuthDeviceView, PendingWebauthnAssertion, PendingWebauthnRegistration,
    RegisteredWebauthnDevice,
};
use super::DeviceError;
use crate::security::random_token_part;

fn user_uuid(user: &RecordId) -> uuid::Uuid {
    uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, bare_id(user).as_bytes())
}

fn credential_id_string(passkey: &Passkey) -> Result<String, DeviceError> {
    let value = serde_json::to_value(passkey.cred_id()).map_err(|_| DeviceError::Store)?;
    value.as_str().map(str::to_owned).ok_or(DeviceError::Store)
}

fn passkey_to_json(passkey: &Passkey) -> Result<Value, DeviceError> {
    serde_json::to_value(passkey).map_err(|_| DeviceError::Store)
}

fn passkey_from_json(value: &Value) -> Result<Passkey, DeviceError> {
    serde_json::from_value(value.clone()).map_err(|_| DeviceError::Store)
}

async fn load_user_passkeys(
    valence: &Valence,
    user: &RecordId,
) -> Result<Vec<(String, Passkey)>, DeviceError> {
    let uid = bare_id(user);
    let rows = AuthDevice::get_from_user_id_used(
        &uid,
        valence,
        valence::use_!(r"When you **sign in with a security key or passkey**, we **list your trusted devices** so we can build the challenge from credentials you already registered. Only this assertion flow uses that list."),
    )
    .await
    .map_err(|_| DeviceError::Store)?;
    let mut out = Vec::new();
    for d in rows {
        if *d.kind() != GeneratedKind::Webauthn {
            continue;
        }
        if d.revoked_at().is_some() {
            continue;
        }
        let Some(json) = d.passkey_json() else {
            continue;
        };
        let Some(device_id) = d.id().map(bare_id) else {
            continue;
        };
        let passkey = passkey_from_json(json)?;
        out.push((device_id, passkey));
    }
    Ok(out)
}

/// Begin `WebAuthn` registration for an authenticated user.
///
/// # Errors
///
/// Config / user / store failures.
pub async fn begin_webauthn_registration(
    valence: &Valence,
    rp: &WebauthnRpConfig,
    user: &RecordId,
    label: &str,
) -> Result<PendingWebauthnRegistration, DeviceError> {
    let label = label.trim();
    if label.is_empty() {
        return Err(DeviceError::Config);
    }
    let webauthn = rp.build_webauthn()?;
    let existing = load_user_passkeys(valence, user).await?;
    let exclude: Option<Vec<_>> = if existing.is_empty() {
        None
    } else {
        Some(
            existing
                .iter()
                .map(|(_, pk)| pk.cred_id().clone())
                .collect(),
        )
    };
    let uid = bare_id(user);
    let (ccr, state) = webauthn
        .start_passkey_registration(user_uuid(user), &uid, &uid, exclude)
        .map_err(|_| DeviceError::WebauthnVerifyFailed)?;
    let state_json = serde_json::to_value(&state).map_err(|_| DeviceError::Store)?;
    let creation_options = serde_json::to_value(&ccr).map_err(|_| DeviceError::Store)?;
    let ceremony_id = insert_ceremony(
        valence,
        user,
        AuthDeviceCeremonyPhase::Register,
        Some(label.to_string()),
        state_json,
    )
    .await?;
    tracing::info!(
        operation = "webauthn_registration_begin",
        rp_id = %rp.rp_id,
        "webauthn registration started"
    );
    Ok(PendingWebauthnRegistration {
        ceremony_id,
        creation_options,
    })
}

/// Finish `WebAuthn` registration with the authenticator attestation JSON.
///
/// `attestation_json` is the browser `PublicKeyCredential` / attestation response.
///
/// # Errors
///
/// Ceremony / verify / store failures.
pub async fn finish_webauthn_registration(
    valence: &Valence,
    rp: &WebauthnRpConfig,
    user: &RecordId,
    ceremony_id: &str,
    attestation_json: &Value,
) -> Result<RegisteredWebauthnDevice, DeviceError> {
    let webauthn = rp.build_webauthn()?;
    let ceremony = consume_ceremony(
        valence,
        user,
        ceremony_id,
        AuthDeviceCeremonyPhase::Register,
    )
    .await?;
    let state: PasskeyRegistration = serde_json::from_value(ceremony.state_json().clone())
        .map_err(|_| DeviceError::CeremonyInvalid)?;
    let reg: RegisterPublicKeyCredential = serde_json::from_value(attestation_json.clone())
        .map_err(|_| DeviceError::WebauthnVerifyFailed)?;
    let passkey = webauthn
        .finish_passkey_registration(&reg, &state)
        .map_err(|err| {
            tracing::warn!(
                operation = "webauthn_registration_finish",
                reason_class = "webauthn_verify",
                "webauthn registration verify failed"
            );
            let _ = err;
            DeviceError::WebauthnVerifyFailed
        })?;
    let credential_id = credential_id_string(&passkey)?;
    // Reject duplicate credential ids for this user.
    let uid = bare_id(user);
    let existing = AuthDevice::get_from_user_id_used(
        &uid,
        valence,
        valence::use_!(r"When you **finish registering a security key**, we **list your existing devices** so we can reject a duplicate credential before saving the new one. Only you use the updated device list afterward."),
    )
    .await
    .map_err(|_| DeviceError::Store)?;
    if existing
        .iter()
        .any(|d| d.credential_id().is_some_and(|c| c == &credential_id) && d.revoked_at().is_none())
    {
        return Err(DeviceError::WebauthnVerifyFailed);
    }
    let label = ceremony
        .label()
        .cloned()
        .unwrap_or_else(|| "WebAuthn device".to_string());
    let now = Utc::now();
    let device_id = random_token_part(12);
    let passkey_json = passkey_to_json(&passkey)?;
    let row = AuthDevice::new(
        user.clone(),
        GeneratedKind::Webauthn,
        label,
        None,
        None,
        Some(credential_id.clone()),
        Some(passkey_json),
        Some(0),
        None,
        Some(now),
        Some(now),
        None,
        now,
        now,
    )
    .map_err(|_| DeviceError::Store)?;
    AuthDevice::upsert_used(&device_id, row, valence, valence::use_!(r"When **trusted devices** needs to persist work, we **save Auth Device** so the next step in that feature can continue with the latest values. People and services allowed for **trusted devices** use this data for that workflow—not as a general export of unrelated personal fields."))
        .await
        .map_err(|_| DeviceError::Store)?;
    tracing::info!(
        operation = "webauthn_registration_finish",
        outcome = "ok",
        "webauthn registration finished"
    );
    Ok(RegisteredWebauthnDevice {
        device_id,
        credential_id,
    })
}

/// Begin `WebAuthn` assertion for the user's non-revoked passkeys.
///
/// # Errors
///
/// Config / store / no credentials.
pub async fn begin_webauthn_assertion(
    valence: &Valence,
    rp: &WebauthnRpConfig,
    user: &RecordId,
) -> Result<PendingWebauthnAssertion, DeviceError> {
    let webauthn = rp.build_webauthn()?;
    let existing = load_user_passkeys(valence, user).await?;
    if existing.is_empty() {
        return Err(DeviceError::DeviceMissing);
    }
    let passkeys: Vec<Passkey> = existing.into_iter().map(|(_, pk)| pk).collect();
    let (rcr, state) = webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|_| DeviceError::WebauthnVerifyFailed)?;
    let state_json = serde_json::to_value(&state).map_err(|_| DeviceError::Store)?;
    let request_options = serde_json::to_value(&rcr).map_err(|_| DeviceError::Store)?;
    let ceremony_id = insert_ceremony(
        valence,
        user,
        AuthDeviceCeremonyPhase::Assert,
        None,
        state_json,
    )
    .await?;
    tracing::info!(
        operation = "webauthn_assertion_begin",
        rp_id = %rp.rp_id,
        "webauthn assertion started"
    );
    Ok(PendingWebauthnAssertion {
        ceremony_id,
        request_options,
    })
}

/// Finish `WebAuthn` assertion; updates `sign_count` / `last_seen_at` on the device.
///
/// # Errors
///
/// Ceremony / verify / revoked / store.
pub async fn finish_webauthn_assertion(
    valence: &Valence,
    rp: &WebauthnRpConfig,
    user: &RecordId,
    ceremony_id: &str,
    assertion_json: &Value,
) -> Result<AuthDeviceView, DeviceError> {
    let webauthn = rp.build_webauthn()?;
    let ceremony =
        consume_ceremony(valence, user, ceremony_id, AuthDeviceCeremonyPhase::Assert).await?;
    let state: PasskeyAuthentication = serde_json::from_value(ceremony.state_json().clone())
        .map_err(|_| DeviceError::CeremonyInvalid)?;
    let auth: PublicKeyCredential = serde_json::from_value(assertion_json.clone())
        .map_err(|_| DeviceError::WebauthnVerifyFailed)?;
    let result = webauthn
        .finish_passkey_authentication(&auth, &state)
        .map_err(|err| {
            tracing::warn!(
                operation = "webauthn_assertion_finish",
                reason_class = "webauthn_verify",
                "webauthn assertion verify failed"
            );
            let _ = err;
            DeviceError::WebauthnVerifyFailed
        })?;
    let matched_cred = credential_id_from_result(&result)?;
    let uid = bare_id(user);
    let rows = AuthDevice::get_from_user_id_used(
        &uid,
        valence,
        valence::use_!(r"After a **passkey assertion** succeeds, we **list your devices** so we can find the credential that matched and update when it was last seen. Only your account uses that device record."),
    )
    .await
    .map_err(|_| DeviceError::Store)?;
    let device = rows
        .into_iter()
        .find(|d| {
            *d.kind() == GeneratedKind::Webauthn
                && d.credential_id().is_some_and(|c| c == &matched_cred)
        })
        .ok_or(DeviceError::DeviceMissing)?;
    if device.revoked_at().is_some() {
        return Err(DeviceError::Revoked);
    }
    let label = device.label().clone();
    let trusted_at = device.trusted_at().copied();
    let Some(json) = device.passkey_json().cloned() else {
        return Err(DeviceError::Store);
    };
    let mut passkey = passkey_from_json(&json)?;
    let _ = passkey.update_credential(&result);
    let sign_count = i64::from(result.counter());
    let now = Utc::now();
    let updated_json = passkey_to_json(&passkey)?;
    let device_id = device.id().map(bare_id).ok_or(DeviceError::Store)?;
    device
        .get_mutable_used(valence, valence::use_!(r"In **devices**, we **update this data** so later steps see the latest values for this workflow. Callers allowed for **devices** use the updated data; this is not a public export of unrelated fields."))
        .set_passkey_json(updated_json)
        .map_err(|_| DeviceError::Store)?
        .set_sign_count(sign_count)
        .map_err(|_| DeviceError::Store)?
        .set_last_seen_at(now)
        .map_err(|_| DeviceError::Store)?
        .set_updated_at(now)
        .map_err(|_| DeviceError::Store)?
        .commit()
        .await
        .map_err(|_| DeviceError::Store)?;
    tracing::info!(
        operation = "webauthn_assertion_finish",
        outcome = "ok",
        "webauthn assertion finished"
    );
    Ok(AuthDeviceView {
        id: device_id,
        kind: AuthDeviceKind::WebAuthn,
        label,
        credential_id: Some(matched_cred),
        sign_count: Some(sign_count),
        trusted_at,
        last_seen_at: Some(now),
        revoked_at: None,
    })
}

fn credential_id_from_result(
    result: &webauthn_rs::prelude::AuthenticationResult,
) -> Result<String, DeviceError> {
    let value = serde_json::to_value(result.cred_id()).map_err(|_| DeviceError::Store)?;
    value.as_str().map(str::to_owned).ok_or(DeviceError::Store)
}
