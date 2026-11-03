//! PKCE S256 authorize URL + Valence pending-state put/take (AM-1–AM-3 / K-pkce / K-state).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use crate::support;

use lepton_auth::oauth::{
    begin_oauth, complete_oauth, OAuthClientConfig, OAuthError, OAuthIntent, OAuthProvider,
};
use support::system_valence;

fn live_google_cfg() -> OAuthClientConfig {
    OAuthClientConfig {
        public_base_url: "http://127.0.0.1:3000".into(),
        redirect_path: "/auth/oauth/callback".into(),
        google_client_id: Some("test-google-client-id".into()),
        google_client_secret: Some("test-google-client-secret".into()),
        github_client_id: None,
        github_client_secret: None,
        use_mock_provider: false,
        mock_oidc_issuer_url: None,
        google_token_url: None,
        google_userinfo_url: None,
        github_token_url: None,
        github_user_url: None,
        github_emails_url: None,
    }
}

fn mock_cfg() -> OAuthClientConfig {
    OAuthClientConfig {
        public_base_url: "http://localhost:3000".into(),
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
    }
}

#[tokio::test]
async fn begin_oauth_live_google_scope_profile_and_pkce_happy() {
    let valence = system_valence("oauth_pkce_begin").await;
    let start = begin_oauth(
        &live_google_cfg(),
        &valence,
        OAuthProvider::Google,
        OAuthIntent::Signup,
    )
    .await
    .expect("begin");
    assert!(
        start.authorize_url.contains("openid")
            && start.authorize_url.contains("email")
            && start.authorize_url.contains("profile"),
        "scope must include openid email profile: {}",
        start.authorize_url
    );
    assert!(
        start.authorize_url.contains("code_challenge="),
        "missing code_challenge: {}",
        start.authorize_url
    );
    assert!(
        start.authorize_url.contains("code_challenge_method=S256"),
        "missing S256 method: {}",
        start.authorize_url
    );
    assert!(
        !start.authorize_url.contains("code_verifier"),
        "verifier must not appear on authorize URL"
    );
}

#[tokio::test]
async fn valence_pending_state_take_once_happy_and_double_take_sad() {
    let valence = system_valence("oauth_pkce_state").await;
    let cfg = mock_cfg();
    let start = begin_oauth(&cfg, &valence, OAuthProvider::Google, OAuthIntent::Signup)
        .await
        .expect("begin");
    let first = complete_oauth(
        &cfg,
        &valence,
        OAuthProvider::Google,
        &start.state,
        "mock-code",
    )
    .await
    .expect("first complete");
    assert!(matches!(
        first.completion,
        lepton_auth::oauth::OAuthCompletion::SignedUp { .. }
    ));
    let err = complete_oauth(
        &cfg,
        &valence,
        OAuthProvider::Google,
        &start.state,
        "mock-code",
    )
    .await
    .expect_err("state already consumed");
    assert!(matches!(err, OAuthError::State));
    assert_eq!(err.reason_class(), "oauth_state");
}
