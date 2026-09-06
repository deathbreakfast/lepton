//! Tower-sessions bag keys for AuthDevice binding on an authenticated session.

use tower_sessions::Session;

/// Session key storing the bound `auth_device` id after MFA / skip.
pub const AUTH_DEVICE_ID_KEY: &str = "auth_device_id";

/// Pending MFA: Valence / session user id string.
pub const PENDING_MFA_USER_ID_KEY: &str = "pending_mfa_user_id";
/// Pending MFA: opaque auth hash bytes (session stamp).
pub const PENDING_MFA_AUTH_HASH_KEY: &str = "pending_mfa_auth_hash";
/// Pending MFA: unix expiry seconds.
pub const PENDING_MFA_EXPIRES_KEY: &str = "pending_mfa_expires";
/// Pending MFA: sanitized referer for post-login redirect.
pub const PENDING_MFA_REFERER_KEY: &str = "pending_mfa_referer";
/// Pending MFA: email for session bag after login.
pub const PENDING_MFA_EMAIL_KEY: &str = "pending_mfa_email";
/// Pending MFA: whether primary email is verified (redirect choice).
pub const PENDING_MFA_EMAIL_VERIFIED_KEY: &str = "pending_mfa_email_verified";

/// Default pending MFA lifetime (10 minutes).
pub const PENDING_MFA_TTL_SECS: i64 = 600;

/// Session key: unix seconds when the TOTP sudo window was opened.
pub const STEP_UP_VERIFIED_AT_KEY: &str = "step_up_verified_at";
/// Session key: unix seconds when the TOTP sudo window expires.
pub const STEP_UP_EXPIRES_AT_KEY: &str = "step_up_expires_at";
/// Session key: user id the sudo window is bound to.
pub const STEP_UP_USER_ID_KEY: &str = "step_up_user_id";
/// Session key: auth-hash bytes the sudo window is bound to.
pub const STEP_UP_AUTH_HASH_KEY: &str = "step_up_auth_hash";
/// Session key: step-up scope string.
pub const STEP_UP_SCOPE_KEY: &str = "step_up_scope";
/// Default TOTP sudo window lifetime (5 minutes).
pub const STEP_UP_TTL_SECS: i64 = 300;

/// Read bound device id from the session bag, if any.
pub async fn bound_device_id(session: &Session) -> Option<String> {
    session
        .get::<String>(AUTH_DEVICE_ID_KEY)
        .await
        .ok()
        .flatten()
}

/// Store bound device id after successful MFA / skip / login bind.
///
/// # Errors
///
/// Session store failures.
pub async fn bind_device_id(
    session: &Session,
    device_id: &str,
) -> Result<(), tower_sessions::session::Error> {
    session
        .insert(AUTH_DEVICE_ID_KEY, device_id.to_string())
        .await
}

/// Clear bound device id (e.g. after revoke detection).
pub async fn clear_bound_device_id(session: &Session) {
    let _ = session.remove::<String>(AUTH_DEVICE_ID_KEY).await;
}

/// Clear all pending MFA keys.
pub async fn clear_pending_mfa(session: &Session) {
    let _ = session.remove::<String>(PENDING_MFA_USER_ID_KEY).await;
    let _ = session.remove::<Vec<u8>>(PENDING_MFA_AUTH_HASH_KEY).await;
    let _ = session.remove::<i64>(PENDING_MFA_EXPIRES_KEY).await;
    let _ = session.remove::<String>(PENDING_MFA_REFERER_KEY).await;
    let _ = session.remove::<String>(PENDING_MFA_EMAIL_KEY).await;
    let _ = session.remove::<bool>(PENDING_MFA_EMAIL_VERIFIED_KEY).await;
}

/// Clear the TOTP sudo window keys.
pub async fn clear_step_up_window(session: &Session) {
    let _ = session.remove::<i64>(STEP_UP_VERIFIED_AT_KEY).await;
    let _ = session.remove::<i64>(STEP_UP_EXPIRES_AT_KEY).await;
    let _ = session.remove::<String>(STEP_UP_USER_ID_KEY).await;
    let _ = session.remove::<Vec<u8>>(STEP_UP_AUTH_HASH_KEY).await;
    let _ = session.remove::<String>(STEP_UP_SCOPE_KEY).await;
}
