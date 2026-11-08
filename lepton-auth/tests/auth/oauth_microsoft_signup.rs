//! Microsoft sign-up must not turn the unverified Entra `email` claim into an account email.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use crate::support;

use lepton_auth::oauth::{
    begin_oauth, complete_oauth, OAuthClientConfig, OAuthCompletion, OAuthIntent, OAuthProvider,
};
use lepton_host_adapter::generated::AccountEmail;
use support::system_valence;
use valence::StringPredicate;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn microsoft_signup_does_not_create_verified_email_from_unverified_claim_sad() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "ms.test-access",
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/userinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sub": "ms-sub-attacker",
            "email": "victim@example.test",
            "name": "Attacker",
        })))
        .mount(&server)
        .await;

    let cfg = OAuthClientConfig {
        public_base_url: "http://127.0.0.1:3000".into(),
        redirect_path: "/auth/oauth/callback".into(),
        google_client_id: None,
        google_client_secret: None,
        github_client_id: None,
        github_client_secret: None,
        use_mock_provider: false,
        mock_oidc_issuer_url: None,
        google_token_url: None,
        google_userinfo_url: None,
        github_token_url: None,
        github_user_url: None,
        github_emails_url: None,
        microsoft_client_id: Some("ms-client".into()),
        microsoft_client_secret: Some("ms-secret".into()),
        microsoft_tenant: None,
        microsoft_token_url: Some(format!("{}/token", server.uri())),
        microsoft_userinfo_url: Some(format!("{}/userinfo", server.uri())),
    };
    let valence = system_valence("oauth_ms_unverified_email").await;
    let start = begin_oauth(
        &cfg,
        &valence,
        OAuthProvider::Microsoft,
        OAuthIntent::Signup,
    )
    .await
    .expect("begin");
    let done = complete_oauth(
        &cfg,
        &valence,
        OAuthProvider::Microsoft,
        &start.state,
        "auth-code",
    )
    .await
    .expect("complete");
    assert!(matches!(done.completion, OAuthCompletion::SignedUp { .. }));

    let squatted = AccountEmail::query(&valence, valence::use_!(r"**Test:** Fixture **Account Email** list for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .where_address(StringPredicate::Equals("victim@example.test".into()))
        .first()
        .await
        .expect("query");
    assert!(
        squatted.is_none(),
        "the unverified Microsoft email claim must not be stored as an account email"
    );
}
