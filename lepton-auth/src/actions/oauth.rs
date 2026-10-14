//! OAuth begin / callback server functions (product session login).
//!
//! Account Settings link / unlink lives in [`crate::actions::oauth_settings`].

use leptos::prelude::*;

#[cfg(feature = "ssr")]
fn map_complete_oauth_err(err: crate::oauth::OAuthError) -> ServerFnError {
    use crate::oauth::OAuthError;
    match err {
        OAuthError::AccountTaken => {
            ServerFnError::new("That account is already linked to another user.")
        }
        OAuthError::State => ServerFnError::new("OAuth state invalid or expired"),
        OAuthError::Config => ServerFnError::new("OAuth is not configured"),
        other => ServerFnError::new(other.to_string()),
    }
}

/// Start an OAuth redirect for Google or GitHub.
///
/// Redirects the browser to the provider authorize URL (same window).
/// Uses `OAuthIntent::Signup` so first-time users provision from either sign-in or sign-up.
#[server(BeginOAuth)]
pub async fn begin_oauth(
    /// Provider key: `google` or `github`.
    provider: String,
    /// Optional post-login redirect path (passed through to callback via query when supported).
    referer: Option<String>,
) -> Result<(), ServerFnError> {
    use crate::oauth::{begin_oauth_for_user, OAuthIntent, OAuthProvider};
    use crate::routes::sanitize_referer_path;
    use crate::services::auth_services;

    let referer_path = referer
        .as_ref()
        .map(|r| sanitize_referer_path(Some(r.clone())))
        .filter(|p| p.as_str() != "/");
    let provider = match provider.trim().to_ascii_lowercase().as_str() {
        "google" => OAuthProvider::Google,
        "github" => OAuthProvider::GitHub,
        _ => return Err(ServerFnError::Args("Unknown OAuth provider".into())),
    };
    let services = auth_services().map_err(|e| ServerFnError::new(e.to_string()))?;
    let cfg_snapshot = services
        .oauth
        .get()
        .ok_or_else(|| ServerFnError::new("OAuth is not configured"))?;
    let cfg = cfg_snapshot.as_ref();

    let ctx = higgs::Higgs::from_request().await?;
    let valence = ctx
        .unsafe_system_valence()
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    tracing::info!(
        operation = "oauth_begin",
        provider = provider.as_str(),
        intent = "signup",
        "lepton_auth.oauth.begin"
    );

    let start = begin_oauth_for_user(
        cfg,
        &valence,
        provider,
        OAuthIntent::Signup,
        None,
        referer_path,
    )
    .await
    .map_err(|e| ServerFnError::new(e.to_string()))?;
    leptos_axum::redirect(&start.authorize_url);
    Ok(())
}

/// Complete OAuth after the provider redirects back with `code` and `state`.
///
/// Establishes an axum-login session and redirects to a sanitized path.
/// When `provider` is empty, the CSRF state store supplies the provider.
#[server(CompleteOAuthCallback)]
#[allow(clippy::too_many_lines)] // provider resolve + session MFA + redirect ladder
pub async fn complete_oauth_callback(
    /// Provider key: `google` or `github` (optional when resolvable from `state`).
    provider: String,
    /// Authorization code from the provider.
    code: String,
    /// CSRF state issued by [`begin_oauth`].
    state: String,
    /// Optional post-login redirect path.
    referer: Option<String>,
) -> Result<(), ServerFnError> {
    use crate::oauth::{complete_oauth, peek_oauth_provider, OAuthCompletion, OAuthProvider};
    use crate::routes::{auth_redirect_path, sanitize_referer_path};
    use crate::services::auth_services;
    use crate::session_mfa::{begin_session_for_authenticated_user, SignInOutcome};
    use axum_login::AuthnBackend;
    use leptos_axum::extract;

    let services = auth_services().map_err(|e| ServerFnError::new(e.to_string()))?;
    let cfg_snapshot = services
        .oauth
        .get()
        .ok_or_else(|| ServerFnError::new("OAuth is not configured"))?;
    let cfg = cfg_snapshot.as_ref();

    let ctx = higgs::Higgs::from_request().await?;
    let valence = ctx
        .unsafe_system_valence()
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let provider = if provider.trim().is_empty() {
        peek_oauth_provider(&valence, &state)
            .await
            .map_err(map_complete_oauth_err)?
    } else {
        match provider.trim().to_ascii_lowercase().as_str() {
            "google" => OAuthProvider::Google,
            "github" => OAuthProvider::GitHub,
            _ => return Err(ServerFnError::Args("Unknown OAuth provider".into())),
        }
    };

    let result = complete_oauth(cfg, &valence, provider, &state, &code)
        .await
        .map_err(|e| {
            tracing::warn!(
                operation = "oauth_complete",
                provider = provider.as_str(),
                reason_class = e.reason_class(),
                "lepton_auth.oauth.complete"
            );
            map_complete_oauth_err(e)
        })?;

    let outcome = result.completion;
    let referer = result.referer.or(referer);

    let (user_id, default_redirect) = match outcome {
        OAuthCompletion::LoggedIn { user_id } | OAuthCompletion::SignedUp { user_id } => {
            tracing::info!(
                operation = "oauth_complete",
                provider = provider.as_str(),
                outcome = "ok",
                "lepton_auth.oauth.complete"
            );
            (user_id, "/welcome")
        }
        OAuthCompletion::Linked { user_id } => {
            tracing::info!(
                operation = "oauth_complete",
                provider = provider.as_str(),
                outcome = "ok",
                "lepton_auth.oauth.complete"
            );
            // Link flows return to Account Settings when the IdP drops `referer`.
            (user_id, crate::paths::USER_ACCOUNT_SETTINGS)
        }
        OAuthCompletion::NeedsLink { .. } => {
            tracing::info!(
                operation = "oauth_complete",
                provider = provider.as_str(),
                outcome = "needs_link",
                "lepton_auth.oauth.complete"
            );
            return Err(ServerFnError::new(
                "No account linked for this identity. Sign in and link it from Account Settings, or create an account first.",
            ));
        }
    };

    let mut auth_session: axum_login::AuthSession<lepton_host_adapter::Backend> = extract().await?;
    let backend = auth_session.backend.clone();
    let session_user_id = user_id.to_string();
    let user = backend
        .get_user(&session_user_id)
        .await
        .map_err(|e| ServerFnError::new(format!("Load user failed: {e}")))?
        .ok_or_else(|| ServerFnError::new("OAuth user not found"))?;

    let session: tower_sessions::Session = extract().await?;
    let cookie = {
        use crate::devices::{DeviceBindingCookie, DEVICE_BINDING_COOKIE};
        use http::header::COOKIE;
        let headers: http::HeaderMap = extract().await.unwrap_or_default();
        headers
            .get(COOKIE)
            .and_then(|v| v.to_str().ok())
            .and_then(|cookie_header| {
                cookie_header.split(';').find_map(|part| {
                    let part = part.trim();
                    let (name, value) = part.split_once('=')?;
                    if name.trim() == DEVICE_BINDING_COOKIE {
                        DeviceBindingCookie::parse(value.trim())
                    } else {
                        None
                    }
                })
            })
    };

    let path = sanitize_referer_path(referer);
    let referer_opt = if path == "/" {
        None
    } else {
        Some(path.clone())
    };

    match begin_session_for_authenticated_user(
        &mut auth_session,
        &session,
        &valence,
        &user,
        referer_opt.clone(),
        cookie.as_ref(),
    )
    .await
    {
        Ok(SignInOutcome::Completed { email_verified: _ }) => {
            let redirect_to = if path == "/" {
                auth_redirect_path(default_redirect.to_string())
            } else {
                auth_redirect_path(path)
            };
            leptos_axum::redirect(&redirect_to);
            Ok(())
        }
        Ok(SignInOutcome::NeedsMfa { .. }) => {
            // Pending MFA stored; send user to sign-in MFA step.
            leptos_axum::redirect(&auth_redirect_path(format!(
                "{}?mfa=1",
                crate::paths::SIGNIN
            )));
            Ok(())
        }
        Err(e) => Err(ServerFnError::new(e.to_string())),
    }
}
