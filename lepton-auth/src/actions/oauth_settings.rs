//! OAuth link / unlink server functions for Account Settings.
//!
//! Signed-in product UI wraps [`crate::oauth`] library APIs with
//! [`OAuthIntent::Link`](crate::oauth::OAuthIntent::Link). Hosts show
//! `LinkedIdentityView` rows (no `provider_subject`), start link redirects,
//! and unlink with a last sign-in method guard.
//!
//! # Examples
//!
//! ```rust,ignore
//! use lepton_auth::actions::oauth_settings::{
//!     begin_oauth_link, list_linked_identities_ui, unlink_oauth_identity_ui,
//! };
//!
//! async fn connect_github_from_settings() -> Result<(), leptos::prelude::ServerFnError> {
//!     let links = list_linked_identities_ui().await?;
//!     if !links.iter().any(|l| l.provider == "github") {
//!         begin_oauth_link("github".into(), Some("/user/account-settings".into())).await?;
//!     }
//!     Ok(())
//! }
//!
//! async fn unlink_row(linked_id: String) -> Result<(), leptos::prelude::ServerFnError> {
//!     unlink_oauth_identity_ui(linked_id).await
//! }
//! ```

use chrono::{DateTime, Utc};
use leptos::prelude::*;
use serde::{Deserialize, Serialize};

/// Safe list view for a linked OAuth identity (no `provider_subject`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinkedIdentityView {
    /// Valence `linked_identity` id.
    pub id: String,
    /// Provider key: `google` or `github`.
    pub provider: String,
    /// Optional email hint from the identity provider (owner-visible).
    pub email_hint: Option<String>,
    /// When the identity was linked.
    pub linked_at: DateTime<Utc>,
}

#[cfg(feature = "ssr")]
fn map_oauth_err(err: crate::oauth::OAuthError) -> ServerFnError {
    use crate::oauth::OAuthError;
    match err {
        OAuthError::AccountTaken => {
            ServerFnError::new("That account is already linked to another user.")
        }
        OAuthError::LinkMissing => ServerFnError::new("That linked account was not found."),
        OAuthError::State => ServerFnError::new("OAuth state invalid or expired"),
        OAuthError::Config => ServerFnError::new("OAuth is not configured"),
        other => ServerFnError::new(other.to_string()),
    }
}

#[cfg(feature = "ssr")]
async fn oauth_settings_valence(
) -> Result<(higgs::Higgs, lepton_host_adapter::User, valence::Valence), ServerFnError> {
    let (ctx, auth_user) = crate::ssr_support::require_auth_user().await?;
    let valence = ctx
        .unsafe_system_valence()
        .map_err(|e| crate::ssr_support::map_higgs_err(&e))?;
    Ok((ctx, auth_user, valence))
}

#[cfg(feature = "ssr")]
fn parse_provider(provider: &str) -> Result<crate::oauth::OAuthProvider, ServerFnError> {
    match provider.trim().to_ascii_lowercase().as_str() {
        "google" => Ok(crate::oauth::OAuthProvider::Google),
        "github" => Ok(crate::oauth::OAuthProvider::GitHub),
        _ => Err(ServerFnError::Args("Unknown OAuth provider".into())),
    }
}

/// Build a client-safe view from a Valence row (omits `provider_subject`).
#[cfg(feature = "ssr")]
#[must_use]
pub fn linked_identity_to_view(
    row: &lepton_host_adapter::generated::LinkedIdentity,
) -> Option<LinkedIdentityView> {
    let id = row.id()?.id().to_string();
    Some(LinkedIdentityView {
        id,
        provider: row.provider().as_str().to_string(),
        email_hint: row.email_hint().cloned(),
        linked_at: *row.linked_at(),
    })
}

/// Whether the user has a stored password hash (password sign-in available).
#[cfg(feature = "ssr")]
pub async fn user_has_password(
    valence: &valence::Valence,
    user: &valence::RecordId,
) -> Result<bool, crate::oauth::OAuthError> {
    use lepton_host_adapter::generated::User;
    use valence::Model;

    let bare = valence::extract_id_from_record(user).unwrap_or_else(|_| user.id().to_string());
    let row = User::get_used(&bare, valence, valence::use_!("get User in src/actions/oauth_settings.rs; Valence persistence for this feature path; typed store; visible to session actor / service path."))
        .await
        .map_err(|_| crate::oauth::OAuthError::Store)?
        .ok_or(crate::oauth::OAuthError::UserMissing)?;
    Ok(row.password_hash().is_some_and(|h| !h.trim().is_empty()))
}

/// True when unlinking `linked_id` would remove the only OAuth link and the user
/// has no password (would leave no sign-in method).
#[cfg(feature = "ssr")]
pub async fn would_remove_last_sign_in_method(
    valence: &valence::Valence,
    user: &valence::RecordId,
    linked_id: &valence::RecordId,
) -> Result<bool, crate::oauth::OAuthError> {
    if user_has_password(valence, user).await? {
        return Ok(false);
    }
    let links = crate::oauth::list_linked_identities(valence, user).await?;
    let target =
        valence::extract_id_from_record(linked_id).unwrap_or_else(|_| linked_id.id().to_string());
    let has_target = links
        .iter()
        .any(|l| l.id().is_some_and(|id| id.id() == target.as_str()));
    if !has_target {
        return Ok(false);
    }
    Ok(links.len() <= 1)
}

/// List linked OAuth identities for the signed-in user.
#[server(ListLinkedIdentitiesUi)]
pub async fn list_linked_identities_ui() -> Result<Vec<LinkedIdentityView>, ServerFnError> {
    let (_ctx, auth_user, valence) = oauth_settings_valence().await?;
    tracing::info!(
        operation = "oauth_list",
        outcome = "start",
        "lepton_auth.oauth.list"
    );
    let rows = crate::oauth::list_linked_identities(&valence, &auth_user.id)
        .await
        .map_err(|e| {
            tracing::warn!(
                operation = "oauth_list",
                outcome = "error",
                reason_class = e.reason_class(),
                "lepton_auth.oauth.list"
            );
            map_oauth_err(e)
        })?;
    let views: Vec<_> = rows.iter().filter_map(linked_identity_to_view).collect();
    tracing::info!(
        operation = "oauth_list",
        outcome = "ok",
        "lepton_auth.oauth.list"
    );
    Ok(views)
}

/// Start an OAuth redirect to link a provider to the signed-in user.
///
/// Uses [`OAuthIntent::Link`](crate::oauth::OAuthIntent::Link) with the session
/// user bound into CSRF state (never a client-supplied user id).
#[server(BeginOAuthLink)]
pub async fn begin_oauth_link(
    /// Provider key: `google` or `github`.
    provider: String,
    /// Post-link redirect path (defaults to account settings when unset).
    referer: Option<String>,
) -> Result<(), ServerFnError> {
    use crate::oauth::{begin_oauth_for_user, OAuthIntent};
    use crate::paths::USER_ACCOUNT_SETTINGS;
    use crate::routes::sanitize_referer_path;
    use crate::services::auth_services;

    let (_ctx, auth_user, valence) = oauth_settings_valence().await?;
    let provider = parse_provider(&provider)?;
    let referer_path = referer
        .as_ref()
        .map(|r| sanitize_referer_path(Some(r.clone())))
        .filter(|p| p.as_str() != "/")
        .unwrap_or_else(|| USER_ACCOUNT_SETTINGS.to_string());

    let services = auth_services().map_err(|e| ServerFnError::new(e.to_string()))?;
    let cfg = services
        .oauth
        .as_ref()
        .ok_or_else(|| ServerFnError::new("OAuth is not configured"))?;

    tracing::info!(
        operation = "oauth_begin",
        provider = provider.as_str(),
        intent = "link",
        "lepton_auth.oauth.begin"
    );

    let start = begin_oauth_for_user(
        cfg,
        &valence,
        provider,
        OAuthIntent::Link,
        Some(&auth_user.id),
        Some(referer_path),
    )
    .await
    .map_err(|e| {
        tracing::warn!(
            operation = "oauth_begin",
            provider = provider.as_str(),
            intent = "link",
            reason_class = e.reason_class(),
            "lepton_auth.oauth.begin"
        );
        map_oauth_err(e)
    })?;

    leptos_axum::redirect(&start.authorize_url);
    Ok(())
}

/// Unlink a linked OAuth identity owned by the signed-in user.
///
/// Refuses when the user has no password and this is their only linked identity.
#[server(UnlinkOAuthIdentityUi)]
pub async fn unlink_oauth_identity_ui(
    /// Valence `linked_identity` id.
    linked_id: String,
) -> Result<(), ServerFnError> {
    let (_ctx, auth_user, valence) = oauth_settings_valence().await?;
    let linked = valence::RecordId::new("linked_identity", linked_id.trim());

    tracing::info!(
        operation = "oauth_unlink",
        outcome = "start",
        "lepton_auth.oauth.unlink"
    );

    if would_remove_last_sign_in_method(&valence, &auth_user.id, &linked)
        .await
        .map_err(map_oauth_err)?
    {
        tracing::warn!(
            operation = "oauth_unlink",
            outcome = "error",
            reason_class = "last_sign_in_method",
            "lepton_auth.oauth.unlink"
        );
        return Err(ServerFnError::new(
            "Keep at least one way to sign in. Set a password before unlinking.",
        ));
    }

    crate::oauth::unlink_oauth_identity(&valence, &auth_user.id, &linked)
        .await
        .map_err(|e| {
            tracing::warn!(
                operation = "oauth_unlink",
                outcome = "error",
                reason_class = e.reason_class(),
                "lepton_auth.oauth.unlink"
            );
            map_oauth_err(e)
        })?;

    tracing::info!(
        operation = "oauth_unlink",
        outcome = "ok",
        "lepton_auth.oauth.unlink"
    );
    Ok(())
}

#[cfg(all(test, feature = "ssr"))]
mod view_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn linked_identity_view_omits_provider_subject() {
        let view = LinkedIdentityView {
            id: "abc".into(),
            provider: "google".into(),
            email_hint: Some("a@b.c".into()),
            linked_at: Utc::now(),
        };
        let value = serde_json::to_value(&view).expect("serialize");
        assert!(value.get("provider_subject").is_none());
        assert_eq!(value.get("provider"), Some(&json!("google")));
        assert_eq!(value.get("id"), Some(&json!("abc")));
    }
}
