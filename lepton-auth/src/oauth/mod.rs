//! OAuth login / signup / link (`oauth-google` / `oauth-github` / `oauth-microsoft` + mock provider).
//!
//! **Mock provider** (`OAuthClientConfig::use_mock_provider`): in-process code exchange when
//! `mock_oidc_issuer_url` is unset; HTTP against a lab mock OIDC issuer when set
//! (e.g. `http://127.0.0.1:5556`).
//! **Live Google** (`oauth-google` + client id/secret): authorization-code token + userinfo
//! exchange with scope `openid email profile` and PKCE S256. **Live GitHub**
//! (`oauth-github` + client id/secret): token + user / emails exchange with PKCE S256
//! (subject is the numeric GitHub user id).
//!
//! CSRF + PKCE verifier + optional referer live in Valence table `oauth_pending_state`
//! (short TTL, single consume). Hosts resolve client secrets with the host boot
//! crate `uf-oauth-boot` (Neutrino sealed store) and inject config with
//! [`crate::services::LeptonAuthServicesBuilder::oauth`].
//!
//! Product UI (same-window redirect + axum-login session) uses
//! [`crate::actions::oauth`] (`BeginOAuth` / `CompleteOAuthCallback`) for signup/login
//! and [`crate::actions::oauth_settings`] for Account Settings link / unlink
//! (`OAuthIntent::Link` with the session user bound into CSRF state).
//!
//! Signup with a taken email hint returns [`crate::oauth::OAuthCompletion::NeedsLink`] and does not
//! create User/Account rows. Mock code `no-email` / `noemail:*` provisions without an
//! email hint (founding `Account.user` still set; primaries unset).
//!
//! # Examples
//!
//! Mock provider: begin authorize, complete with a mock code, then link if needed.
//!
//! ```rust,ignore
//! use lepton_auth::oauth::{
//!     begin_oauth, begin_oauth_for_user, complete_oauth, link_oauth_identity,
//!     list_linked_identities, OAuthClientConfig, OAuthCompletion, OAuthIntent,
//!     OAuthProvider,
//! };
//! use valence::{RecordId, Valence};
//!
//! async fn oauth_signup_login_mock(
//!     cfg: &OAuthClientConfig,
//!     v: &Valence,
//! ) -> Result<(), Box<dyn std::error::Error>> {
//!     let start = begin_oauth(cfg, v, OAuthProvider::Google, OAuthIntent::Signup).await?;
//!     let signed_up =
//!         complete_oauth(cfg, v, OAuthProvider::Google, &start.state, "mock-code").await?.completion;
//!     let OAuthCompletion::SignedUp { user_id } = signed_up else {
//!         panic!("expected SignedUp");
//!     };
//!     let start = begin_oauth(cfg, v, OAuthProvider::Google, OAuthIntent::Login).await?;
//!     let logged_in =
//!         complete_oauth(cfg, v, OAuthProvider::Google, &start.state, "mock-code").await?.completion;
//!     assert!(matches!(
//!         logged_in,
//!         OAuthCompletion::LoggedIn { user_id: id } if id == user_id
//!     ));
//!     let _ = list_linked_identities(v, &user_id).await?;
//!     Ok(())
//! }
//!
//! async fn oauth_link_bound_user(
//!     cfg: &OAuthClientConfig,
//!     v: &Valence,
//!     user: &RecordId,
//! ) -> Result<(), Box<dyn std::error::Error>> {
//!     let start =
//!         begin_oauth_for_user(cfg, v, OAuthProvider::GitHub, OAuthIntent::Link, Some(user), None)
//!             .await?;
//!     let outcome =
//!         complete_oauth(cfg, v, OAuthProvider::GitHub, &start.state, "link-me").await?.completion;
//!     assert!(matches!(outcome, OAuthCompletion::Linked { .. }));
//!     Ok(())
//! }
//! ```
//!
//! Live GitHub (feature `oauth-github`; host supplies client id/secret):
//!
//! ```rust,ignore
//! use lepton_auth::oauth::{
//!     begin_oauth, complete_oauth, OAuthClientConfig, OAuthCompletion, OAuthIntent,
//!     OAuthProvider,
//! };
//! use valence::Valence;
//!
//! async fn github_signup_login(
//!     cfg: &OAuthClientConfig,
//!     v: &Valence,
//!     code_signup: &str,
//!     code_login: &str,
//! ) -> Result<(), Box<dyn std::error::Error>> {
//!     let start = begin_oauth(cfg, v, OAuthProvider::GitHub, OAuthIntent::Signup).await?;
//!     let signed_up =
//!         complete_oauth(cfg, v, OAuthProvider::GitHub, &start.state, code_signup).await?.completion;
//!     let OAuthCompletion::SignedUp { user_id } = signed_up else {
//!         panic!("expected SignedUp");
//!     };
//!     let start = begin_oauth(cfg, v, OAuthProvider::GitHub, OAuthIntent::Login).await?;
//!     let logged_in =
//!         complete_oauth(cfg, v, OAuthProvider::GitHub, &start.state, code_login).await?.completion;
//!     assert!(matches!(
//!         logged_in,
//!         OAuthCompletion::LoggedIn { user_id: id } if id == user_id
//!     ));
//!     Ok(())
//! }
//! ```

#[cfg(feature = "ssr")]
mod api;
#[cfg(feature = "ssr")]
mod error;
#[cfg(all(feature = "ssr", feature = "oauth-github"))]
mod github;
#[cfg(all(feature = "ssr", feature = "oauth-google"))]
mod google;
#[cfg(all(feature = "ssr", feature = "oauth-microsoft"))]
mod microsoft;
#[cfg(feature = "ssr")]
mod mock;
#[cfg(feature = "ssr")]
mod mock_http;
#[cfg(feature = "ssr")]
mod provision;
#[cfg(feature = "ssr")]
mod state_store;

#[cfg(feature = "ssr")]
pub use api::{
    begin_oauth, begin_oauth_for_user, complete_oauth, link_oauth_identity, list_linked_identities,
    unlink_oauth_identity, OAuthClientConfig, OAuthCompleteResult, OAuthCompletion, OAuthIntent,
    OAuthProvider, OAuthStart, PendingOAuthLink,
};
#[cfg(feature = "ssr")]
pub use error::OAuthError;

/// Resolve OAuth provider from CSRF `state` without consuming pending state.
///
/// # Errors
///
/// [`OAuthError::State`] when `state` is missing or expired.
#[cfg(feature = "ssr")]
pub async fn peek_oauth_provider(
    valence: &valence::Valence,
    state: &str,
) -> Result<OAuthProvider, OAuthError> {
    state_store::peek_provider(valence, state).await
}
