//! Server function for signing the current user out.

use leptos::prelude::*;

/// Log the current user out and redirect to a sanitized `referer` path (or `/`).
#[server(Logout)]
pub async fn logout(
    /// Optional post-logout redirect path (sanitized server-side).
    referer: Option<String>,
) -> Result<(), ServerFnError> {
    use crate::routes::sanitize_referer_path;
    use leptos_axum::extract;

    let mut auth_session: axum_login::AuthSession<lepton_host_adapter::auth::Backend> =
        extract().await?;

    if let Err(e) = auth_session.logout().await {
        #[cfg(feature = "spectra")]
        crate::spectra_emit::account(
            crate::spectra_emit::AccountOperation::Logout,
            crate::spectra_emit::AuthOutcome::Failure,
            "session",
        );
        return Err(ServerFnError::ServerError(format!("Logout failed: {e}")));
    }

    let session: tower_sessions::Session = extract().await?;
    session.remove::<String>("account_email").await?;
    crate::session_binding::clear_step_up_window(&session).await;
    crate::session_binding::clear_pending_mfa(&session).await;

    let redirect_to = crate::routes::auth_redirect_path(sanitize_referer_path(referer));
    leptos_axum::redirect(&redirect_to);
    #[cfg(feature = "spectra")]
    crate::spectra_emit::account(
        crate::spectra_emit::AccountOperation::Logout,
        crate::spectra_emit::AuthOutcome::Success,
        "none",
    );
    Ok(())
}
