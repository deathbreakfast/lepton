//! `complete_oauth` HTTP mock exchange against ephemeral `mock_oidc`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use lepton_auth::oauth::{
    begin_oauth, complete_oauth, OAuthClientConfig, OAuthCompletion, OAuthIntent, OAuthProvider,
};
use lepton_e2e::boot::boot_valence;
use lepton_e2e::mock_oidc::{serve_for_test, CodeStore};

fn cfg_with_issuer(issuer: &str) -> OAuthClientConfig {
    OAuthClientConfig {
        public_base_url: "http://127.0.0.1:3000".into(),
        redirect_path: "/auth/oauth/callback".into(),
        google_client_id: None,
        google_client_secret: None,
        github_client_id: None,
        github_client_secret: None,
        use_mock_provider: true,
        mock_oidc_issuer_url: Some(issuer.to_string()),
        google_token_url: None,
        google_userinfo_url: None,
        github_token_url: None,
        github_user_url: None,
        github_emails_url: None,
    }
}

#[tokio::test]
async fn begin_oauth_mock_issuer_authorize_url_happy() {
    let cfg = cfg_with_issuer("http://127.0.0.1:5556");
    let valence = boot_valence("oauth-mock-http-begin")
        .await
        .expect("valence");
    let start = begin_oauth(&cfg, &valence, OAuthProvider::Google, OAuthIntent::Signup)
        .await
        .expect("begin");
    assert!(
        start
            .authorize_url
            .starts_with("http://127.0.0.1:5556/authorize?"),
        "{}",
        start.authorize_url
    );
    assert!(!start.authorize_url.contains("/oauth/mock/authorize"));
}

#[tokio::test]
async fn complete_oauth_mock_http_signup_happy() {
    let store = Arc::new(CodeStore::new());
    let (addr, handle) = serve_for_test(SocketAddr::from(([127, 0, 0, 1], 0)), Arc::clone(&store))
        .await
        .expect("bind");
    tokio::time::sleep(Duration::from_millis(20)).await;
    let issuer = format!("http://{addr}");
    let cfg = cfg_with_issuer(&issuer);

    let valence = boot_valence("oauth-mock-http").await.expect("valence");
    let start = begin_oauth(&cfg, &valence, OAuthProvider::Google, OAuthIntent::Signup)
        .await
        .expect("begin");
    let code = store
        .issue_code("google", Some("http-user"))
        .expect("issue");
    let outcome = complete_oauth(&cfg, &valence, OAuthProvider::Google, &start.state, &code)
        .await
        .expect("complete")
        .completion;
    assert!(matches!(outcome, OAuthCompletion::SignedUp { .. }));
    handle.abort();
}

#[tokio::test]
async fn complete_oauth_mock_http_sidecar_down_sad() {
    let cfg = cfg_with_issuer("http://127.0.0.1:59999");
    let valence = boot_valence("oauth-mock-http-down").await.expect("valence");
    let start = begin_oauth(&cfg, &valence, OAuthProvider::Google, OAuthIntent::Signup)
        .await
        .expect("begin");
    let err = complete_oauth(
        &cfg,
        &valence,
        OAuthProvider::Google,
        &start.state,
        "mock-code",
    )
    .await
    .expect_err("down");
    assert!(matches!(err, lepton_auth::oauth::OAuthError::Provider));
}
