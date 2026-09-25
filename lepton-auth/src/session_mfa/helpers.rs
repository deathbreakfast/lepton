//! Shared helpers for pending MFA + login bind.

use chrono::Utc;
use lepton_host_adapter::generated::AuthDevice;
use lepton_host_adapter::generated::AuthDeviceKind as GeneratedKind;
#[cfg(feature = "totp")]
use lepton_host_adapter::generated::TotpFactor;
use lepton_host_adapter::User;
use tower_sessions::Session;
use valence::{RecordId, Valence};

use super::SessionMfaError;
use crate::session_binding::{
    bind_device_id, clear_pending_mfa, PENDING_MFA_AUTH_HASH_KEY, PENDING_MFA_EMAIL_KEY,
    PENDING_MFA_EMAIL_VERIFIED_KEY, PENDING_MFA_EXPIRES_KEY, PENDING_MFA_REFERER_KEY,
    PENDING_MFA_TTL_SECS, PENDING_MFA_USER_ID_KEY,
};

pub(super) fn bare_id(record: &RecordId) -> String {
    valence::extract_id_from_record(record).unwrap_or_else(|_| record.id().to_string())
}

/// Whether the user has an enabled `TotpFactor`.
pub(super) async fn user_has_enabled_totp(
    valence: &Valence,
    user: &RecordId,
) -> Result<bool, SessionMfaError> {
    #[cfg(not(feature = "totp"))]
    {
        let _ = (valence, user);
        Ok(false)
    }
    #[cfg(feature = "totp")]
    {
        let uid = bare_id(user);
        let factors = TotpFactor::get_from_user_id(
            &uid,
            valence,
            valence::use_!(r"After password **sign-in**, we **check whether an authenticator is enabled** so we know if a second factor is required before the session is fully signed in. Only this MFA gate uses that answer."),
        )
        .await
        .map_err(|_| SessionMfaError::Store)?;
        Ok(factors.iter().any(|f| f.enabled_at().is_some()))
    }
}

/// Whether the user has a non-revoked `WebAuthn` device.
pub(super) async fn user_has_webauthn(
    valence: &Valence,
    user: &RecordId,
) -> Result<bool, SessionMfaError> {
    let uid = bare_id(user);
    let devices = AuthDevice::get_from_user_id(
        &uid,
        valence,
        valence::use_!(r"After password **sign-in**, we **check whether a security key is registered** so we know if a passkey challenge is required before the session is fully signed in. Only this MFA gate uses that answer."),
    )
    .await
    .map_err(|_| SessionMfaError::Store)?;
    Ok(devices.iter().any(|d| {
        *d.kind() == GeneratedKind::Webauthn && d.revoked_at().is_none() && d.trusted_at().is_some()
    }))
}

pub(super) struct PendingMfa {
    pub user_id: String,
    /// Compared in TOTP / `WebAuthn` complete paths (feature-gated readers).
    #[allow(dead_code)]
    pub auth_hash: Vec<u8>,
    /// Returned from MFA complete for post-login redirect (feature-gated readers).
    #[allow(dead_code)]
    pub referer: Option<String>,
}

pub(super) async fn store_pending_mfa(
    session: &Session,
    user: &User,
    referer: Option<String>,
) -> Result<(), SessionMfaError> {
    clear_pending_mfa(session).await;
    let expires = Utc::now().timestamp() + PENDING_MFA_TTL_SECS;
    session
        .insert(PENDING_MFA_USER_ID_KEY, user.session_id.clone())
        .await
        .map_err(|_| SessionMfaError::Session)?;
    session
        .insert(PENDING_MFA_AUTH_HASH_KEY, user.session_stamp.clone())
        .await
        .map_err(|_| SessionMfaError::Session)?;
    session
        .insert(PENDING_MFA_EXPIRES_KEY, expires)
        .await
        .map_err(|_| SessionMfaError::Session)?;
    session
        .insert(PENDING_MFA_EMAIL_KEY, user.email.clone())
        .await
        .map_err(|_| SessionMfaError::Session)?;
    session
        .insert(PENDING_MFA_EMAIL_VERIFIED_KEY, user.email_verified)
        .await
        .map_err(|_| SessionMfaError::Session)?;
    if let Some(r) = referer {
        session
            .insert(PENDING_MFA_REFERER_KEY, r)
            .await
            .map_err(|_| SessionMfaError::Session)?;
    }
    Ok(())
}

pub(super) async fn load_pending_mfa(session: &Session) -> Result<PendingMfa, SessionMfaError> {
    let user_id = session
        .get::<String>(PENDING_MFA_USER_ID_KEY)
        .await
        .map_err(|_| SessionMfaError::Session)?
        .ok_or(SessionMfaError::PendingMissing)?;
    let auth_hash = session
        .get::<Vec<u8>>(PENDING_MFA_AUTH_HASH_KEY)
        .await
        .map_err(|_| SessionMfaError::Session)?
        .ok_or(SessionMfaError::PendingMissing)?;
    let expires = session
        .get::<i64>(PENDING_MFA_EXPIRES_KEY)
        .await
        .map_err(|_| SessionMfaError::Session)?
        .ok_or(SessionMfaError::PendingMissing)?;
    if Utc::now().timestamp() > expires {
        clear_pending_mfa(session).await;
        return Err(SessionMfaError::PendingExpired);
    }
    let email = session
        .get::<String>(PENDING_MFA_EMAIL_KEY)
        .await
        .map_err(|_| SessionMfaError::Session)?
        .ok_or(SessionMfaError::PendingMissing)?;
    let _email_verified = session
        .get::<bool>(PENDING_MFA_EMAIL_VERIFIED_KEY)
        .await
        .map_err(|_| SessionMfaError::Session)?
        .unwrap_or(false);
    let _ = email;
    let referer = session
        .get::<String>(PENDING_MFA_REFERER_KEY)
        .await
        .map_err(|_| SessionMfaError::Session)?;
    Ok(PendingMfa {
        user_id,
        auth_hash,
        referer,
    })
}

pub(super) async fn finalize_login(
    auth_session: &mut axum_login::AuthSession<lepton_host_adapter::Backend>,
    session: &Session,
    user: &User,
    device_id: Option<&str>,
) -> Result<(), SessionMfaError> {
    auth_session
        .login(user)
        .await
        .map_err(|_| SessionMfaError::Login)?;
    session
        .insert("account_email", user.email.clone())
        .await
        .map_err(|_| SessionMfaError::Session)?;
    clear_pending_mfa(session).await;
    if let Some(id) = device_id {
        bind_device_id(session, id)
            .await
            .map_err(|_| SessionMfaError::Session)?;
    }
    Ok(())
}
