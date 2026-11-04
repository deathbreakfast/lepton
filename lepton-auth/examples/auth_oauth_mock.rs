//! Teaching example B4: OAuth mock provider login / link.
//!
//! Library path only (`begin_oauth` / `complete_oauth`). Product UI establishes an
//! axum-login session via `actions::oauth::BeginOAuth` / `CompleteOAuthCallback`
//! after the same library complete step.
//!
//! ```bash
//! cargo check -p lepton-auth --example auth_oauth_mock --features "ssr,oauth-github"
//! ```

#![allow(dead_code)]

use lepton_auth::oauth::{
    begin_oauth, complete_oauth, link_oauth_identity, list_linked_identities,
    unlink_oauth_identity, OAuthClientConfig, OAuthCompletion, OAuthIntent, OAuthProvider,
};
use valence::Valence;

async fn oauth_login_mock(
    cfg: &OAuthClientConfig,
    v: &Valence,
    authenticated_user: valence::RecordId,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = begin_oauth(cfg, v, OAuthProvider::GitHub, OAuthIntent::Login).await?;
    // Host redirects the browser to `start.authorize_url`, then receives `code` + `state`.
    let outcome = complete_oauth(cfg, v, OAuthProvider::GitHub, &start.state, "mock-code")
        .await?
        .completion;
    match outcome {
        OAuthCompletion::LoggedIn { user_id }
        | OAuthCompletion::SignedUp { user_id }
        | OAuthCompletion::Linked { user_id } => {
            let links = list_linked_identities(v, &user_id).await?;
            assert!(!links.is_empty());
        }
        OAuthCompletion::NeedsLink { pending } => {
            link_oauth_identity(v, &authenticated_user, &pending).await?;
            let links = list_linked_identities(v, &authenticated_user).await?;
            assert!(!links.is_empty());
        }
    }
    Ok(())
}

async fn unlink_github(
    v: &Valence,
    user: valence::RecordId,
) -> Result<(), Box<dyn std::error::Error>> {
    let links = list_linked_identities(v, &user).await?;
    if let Some(id) = links
        .iter()
        .find(|l| *l.provider() == lepton_host_adapter::generated::LinkedIdentityProvider::Github)
    {
        if let Some(rid) = id.id() {
            unlink_oauth_identity(v, &user, rid).await?;
        }
    }
    Ok(())
}

fn main() {
    let _ = (oauth_login_mock, unlink_github);
    let _ = OAuthClientConfig {
        public_base_url: "http://127.0.0.1:3000".into(),
        redirect_path: "/auth/oauth/callback".into(),
        google_client_id: None,
        google_client_secret: None,
        github_client_id: None,
        github_client_secret: None,
        use_mock_provider: true,
        mock_oidc_issuer_url: None,
        google_token_url: None,
        google_userinfo_url: None,
        github_token_url: None,
        github_user_url: None,
        github_emails_url: None,
        microsoft_client_id: None,
        microsoft_client_secret: None,
        microsoft_tenant: None,
        microsoft_token_url: None,
        microsoft_userinfo_url: None,
    };
}
