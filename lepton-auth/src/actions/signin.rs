//! Server functions for signing in with email/password and completing MFA.

use leptos::prelude::*;
use serde::{Deserialize, Serialize};

/// Outcome returned to the sign-in UI (MFA step or completed + redirect).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SigninClientOutcome {
    /// Session established. Client should navigate to [`Self::Completed::redirect_to`]
    /// (server also issues a redirect header when possible).
    Completed {
        /// In-app path after login (confirm funnel when email is unverified).
        redirect_to: String,
    },
    /// Show MFA UI; optional `WebAuthn` button when `has_webauthn`.
    NeedsMfa {
        /// User has a non-revoked `WebAuthn` device.
        has_webauthn: bool,
    },
}

/// Post-login landing: the confirm funnel (keeping the referer) when the email is unverified;
/// else the sanitized referer.
#[cfg(feature = "ssr")]
fn post_login_path(email_verified: bool, referer: Option<String>) -> String {
    use crate::routes::{
        auth_redirect_path, confirm_account_path_with_referer, sanitize_referer_path,
    };

    let path = sanitize_referer_path(referer);
    if !email_verified {
        // Already sanitized; a second pass would decode the encoded `referer=` value.
        return confirm_account_path_with_referer(&path);
    }
    let redirect_to = if path == "/" {
        "/welcome".to_string()
    } else {
        path
    };
    auth_redirect_path(redirect_to)
}

#[cfg(feature = "ssr")]
fn redirect_after_login(email_verified: bool, referer: Option<String>) -> String {
    let redirect_to = post_login_path(email_verified, referer);
    leptos_axum::redirect(&redirect_to);
    redirect_to
}

#[cfg(feature = "ssr")]
async fn device_cookie_from_request() -> Option<crate::devices::DeviceBindingCookie> {
    use crate::devices::{DeviceBindingCookie, DEVICE_BINDING_COOKIE};
    use http::header::COOKIE;
    use leptos_axum::extract;

    let headers: http::HeaderMap = extract().await.ok()?;
    let cookie_header = headers.get(COOKIE)?.to_str().ok()?;
    for part in cookie_header.split(';') {
        let part = part.trim();
        let Some((name, value)) = part.split_once('=') else {
            continue;
        };
        if name.trim() == DEVICE_BINDING_COOKIE {
            return DeviceBindingCookie::parse(value.trim());
        }
    }
    None
}

/// Max-Age for the `TrustedBrowser` MFA-skip cookie (30 days).
#[cfg(feature = "ssr")]
pub const DEVICE_BINDING_MAX_AGE_SECS: i64 = 2_592_000;

#[cfg(feature = "ssr")]
fn set_device_binding_cookie(cookie: &crate::devices::DeviceBindingCookie) {
    use crate::devices::DEVICE_BINDING_COOKIE;
    use http::header::{HeaderName, HeaderValue};
    use leptos::prelude::expect_context;
    use leptos_axum::ResponseOptions;

    let secure = !cfg!(debug_assertions);
    let flags = if secure {
        format!("Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age={DEVICE_BINDING_MAX_AGE_SECS}")
    } else {
        format!("Path=/; HttpOnly; SameSite=Lax; Max-Age={DEVICE_BINDING_MAX_AGE_SECS}")
    };
    let value = format!("{DEVICE_BINDING_COOKIE}={}; {flags}", cookie.encode());
    if let Ok(hv) = HeaderValue::from_str(&value) {
        let opts = expect_context::<ResponseOptions>();
        opts.append_header(HeaderName::from_static("set-cookie"), hv);
    }
}

#[cfg(feature = "ssr")]
fn map_mfa_err(err: crate::session_mfa::SessionMfaError) -> ServerFnError {
    match err {
        crate::session_mfa::SessionMfaError::InvalidCredentials => {
            ServerFnError::Args("Invalid credentials".into())
        }
        crate::session_mfa::SessionMfaError::TotpInvalid => {
            ServerFnError::Args("Invalid authentication code".into())
        }
        other => ServerFnError::ServerError(other.to_string()),
    }
}

#[cfg(all(feature = "ssr", feature = "webauthn"))]
fn pending_user_record_id(user_id: &str) -> valence::RecordId {
    let bare = user_id.strip_prefix("user:").unwrap_or(user_id);
    valence::RecordId::new("user", bare)
}

/// Authenticate, optionally enter MFA, or complete login (with TrustedBrowser skip).
#[server(Signin)]
pub async fn signin(
    /// Account email.
    email: String,
    /// Account password.
    password: String,
    /// Optional post-signin redirect path (sanitized server-side).
    referer: Option<String>,
) -> Result<SigninClientOutcome, ServerFnError> {
    use crate::routes::sanitize_referer_path;
    use crate::security::log_credential_audit;
    use crate::session_mfa::{begin_password_sign_in, SignInOutcome};
    use leptos_axum::extract;

    if email.trim().is_empty() || password.is_empty() {
        return Err(ServerFnError::Args("Missing fields".into()));
    }

    let mut auth_session: axum_login::AuthSession<lepton_host_adapter::auth::Backend> =
        extract().await?;
    let session: tower_sessions::Session = extract().await?;
    let ctx = higgs::Higgs::from_request().await?;
    let valence = ctx
        .unsafe_system_valence()
        .map_err(|e| crate::ssr_support::map_higgs_err(&e))?;

    tracing::info!(
        reason_class = "signin_attempt",
        "signin attempt (email omitted)"
    );

    let email_for_audit = email.trim().to_string();
    let cookie = device_cookie_from_request().await;
    let referer = referer
        .map(|r| sanitize_referer_path(Some(r)))
        .filter(|p| p != "/");

    match begin_password_sign_in(
        &mut auth_session,
        &session,
        &valence,
        email,
        password,
        referer.clone(),
        cookie.as_ref(),
    )
    .await
    {
        Ok(SignInOutcome::Completed { email_verified }) => {
            log_credential_audit(
                "signin",
                Some(email_for_audit.as_str()),
                "success",
                Some("authenticated"),
            );
            let redirect_to = redirect_after_login(email_verified, referer);
            Ok(SigninClientOutcome::Completed { redirect_to })
        }
        Ok(SignInOutcome::NeedsMfa { has_webauthn }) => {
            log_credential_audit(
                "signin",
                Some(email_for_audit.as_str()),
                "success",
                Some("needs_mfa"),
            );
            Ok(SigninClientOutcome::NeedsMfa { has_webauthn })
        }
        Err(e) => {
            if e.reason_class() == "invalid_credentials" {
                log_credential_audit(
                    "signin",
                    Some(email_for_audit.as_str()),
                    "failure",
                    Some("invalid_credentials"),
                );
            }
            Err(map_mfa_err(e))
        }
    }
}

/// Complete pending MFA with a six-digit TOTP or unused recovery code; optionally remember this browser.
#[server(CompleteMfaTotp)]
pub async fn complete_mfa_totp(
    /// Authenticator code (six digits) or one-time recovery code.
    code: String,
    /// When true, mint `TrustedBrowser` binding cookie.
    remember: Option<String>,
) -> Result<SigninClientOutcome, ServerFnError> {
    use crate::session_mfa::{complete_sign_in_totp, RememberDevice, SignInOutcome};
    use leptos_axum::extract;

    if code.trim().is_empty() {
        return Err(ServerFnError::Args("Missing code".into()));
    }

    let remember_flag = remember
        .as_deref()
        .is_some_and(|s| s == "true" || s == "on" || s == "1");

    let mut auth_session: axum_login::AuthSession<lepton_host_adapter::auth::Backend> =
        extract().await?;
    let session: tower_sessions::Session = extract().await?;
    let ctx = higgs::Higgs::from_request().await?;
    let valence = ctx
        .unsafe_system_valence()
        .map_err(|e| crate::ssr_support::map_higgs_err(&e))?;
    let services = crate::auth_services().map_err(|e| ServerFnError::new(e.to_string()))?;

    let result = complete_sign_in_totp(
        &mut auth_session,
        &session,
        &valence,
        services,
        code.trim(),
        RememberDevice::from_bool(remember_flag),
    )
    .await
    .map_err(map_mfa_err)?;

    if let Some(cookie) = result.binding_cookie.as_ref() {
        set_device_binding_cookie(cookie);
    }

    match result.outcome {
        SignInOutcome::Completed { email_verified } => {
            let redirect_to = redirect_after_login(email_verified, result.referer);
            Ok(SigninClientOutcome::Completed { redirect_to })
        }
        SignInOutcome::NeedsMfa { .. } => Err(ServerFnError::ServerError(
            "unexpected needs_mfa after complete".into(),
        )),
    }
}

/// Begin WebAuthn assertion for pending MFA (pre-login).
#[server(BeginMfaWebauthn)]
#[allow(clippy::unused_async)] // `#[server]` must be async; body awaits only with `webauthn`
pub async fn begin_mfa_webauthn() -> Result<crate::devices::PendingWebauthnAssertion, ServerFnError>
{
    #[cfg(not(feature = "webauthn"))]
    {
        Err(ServerFnError::ServerError(
            "webauthn feature disabled".into(),
        ))
    }
    #[cfg(feature = "webauthn")]
    {
        use crate::session_mfa::pending_mfa_user_id;
        use leptos_axum::extract;

        let session: tower_sessions::Session = extract().await?;
        let user_id = pending_mfa_user_id(&session).await.map_err(map_mfa_err)?;
        let ctx = higgs::Higgs::from_request().await?;
        let valence = ctx
            .unsafe_system_valence()
            .map_err(|e| crate::ssr_support::map_higgs_err(&e))?;
        let services = crate::auth_services().map_err(|e| ServerFnError::new(e.to_string()))?;
        let rp = services
            .require_webauthn_rp()
            .map_err(|e| ServerFnError::new(e.to_string()))?;

        let user = pending_user_record_id(&user_id);
        crate::devices::begin_webauthn_assertion(&valence, rp, &user)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))
    }
}

/// Finish WebAuthn assertion for pending MFA and establish the session.
#[server(FinishMfaWebauthn)]
#[allow(clippy::unused_async)] // `#[server]` must be async; body awaits only with `webauthn`
pub async fn finish_mfa_webauthn(
    /// Ceremony id from [`begin_mfa_webauthn`].
    ceremony_id: String,
    /// Assertion JSON from `navigator.credentials.get`.
    assertion_json: String,
) -> Result<SigninClientOutcome, ServerFnError> {
    #[cfg(not(feature = "webauthn"))]
    {
        let _ = (ceremony_id, assertion_json);
        Err(ServerFnError::ServerError(
            "webauthn feature disabled".into(),
        ))
    }
    #[cfg(feature = "webauthn")]
    {
        use crate::session_mfa::{complete_sign_in_webauthn, SignInOutcome};
        use leptos_axum::extract;

        let mut auth_session: axum_login::AuthSession<lepton_host_adapter::auth::Backend> =
            extract().await?;
        let session: tower_sessions::Session = extract().await?;
        let ctx = higgs::Higgs::from_request().await?;
        let valence = ctx
            .unsafe_system_valence()
            .map_err(|e| crate::ssr_support::map_higgs_err(&e))?;
        let services = crate::auth_services().map_err(|e| ServerFnError::new(e.to_string()))?;
        let rp = services
            .require_webauthn_rp()
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        let assertion: serde_json::Value = serde_json::from_str(assertion_json.trim())
            .map_err(|e| ServerFnError::new(format!("Invalid assertion: {e}")))?;

        let result = complete_sign_in_webauthn(
            &mut auth_session,
            &session,
            &valence,
            rp,
            &ceremony_id,
            &assertion,
        )
        .await
        .map_err(map_mfa_err)?;

        match result.outcome {
            SignInOutcome::Completed { email_verified } => {
                let redirect_to = redirect_after_login(email_verified, result.referer);
                Ok(SigninClientOutcome::Completed { redirect_to })
            }
            SignInOutcome::NeedsMfa { .. } => Err(ServerFnError::ServerError(
                "unexpected needs_mfa after webauthn".into(),
            )),
        }
    }
}

#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::post_login_path;

    #[test]
    fn unverified_keeps_referer_on_confirm_path_happy() {
        assert_eq!(
            post_login_path(false, Some("/counter/high-scores".into())),
            "/user/confirm-account?referer=%2Fcounter%2Fhigh-scores"
        );
    }

    #[test]
    fn unverified_without_safe_referer_uses_plain_confirm_path_sad() {
        assert_eq!(post_login_path(false, None), "/user/confirm-account");
        assert_eq!(
            post_login_path(false, Some("https://evil.example/x".into())),
            "/user/confirm-account"
        );
    }

    #[test]
    fn verified_lands_on_referer_or_welcome_happy() {
        assert_eq!(post_login_path(true, Some("/counter".into())), "/counter");
        assert_eq!(post_login_path(true, None), "/welcome");
    }
}
