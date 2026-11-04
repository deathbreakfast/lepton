//! Live Google OAuth authorization-code exchange (token + `OpenID` userinfo).

use serde::Deserialize;
use std::time::Duration;

use super::api::OAuthClientConfig;
use super::error::OAuthError;

/// Default Google OAuth 2.0 token endpoint.
pub const DEFAULT_GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
/// Default `OpenID` Connect userinfo endpoint.
pub const DEFAULT_GOOGLE_USERINFO_URL: &str = "https://openidconnect.googleapis.com/v1/userinfo";

const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UserInfoResponse {
    sub: Option<String>,
    email: Option<String>,
    name: Option<String>,
}

/// Exchange an authorization `code` for `(provider_subject, email_hint, name_hint)`.
///
/// # Errors
///
/// [`OAuthError::Config`] when client id/secret missing.
/// [`OAuthError::Provider`] on HTTP / parse / missing `sub` (no secrets in errors).
pub(super) async fn exchange_google_code(
    cfg: &OAuthClientConfig,
    code: &str,
    code_verifier: &str,
) -> Result<(String, Option<String>, Option<String>), OAuthError> {
    let client_id = cfg
        .google_client_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or(OAuthError::Config)?;
    let client_secret = cfg
        .google_client_secret
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or(OAuthError::Config)?;
    let code = code.trim();
    if code.is_empty() {
        return Err(OAuthError::Provider);
    }

    let token_url = cfg
        .google_token_url
        .as_deref()
        .unwrap_or(DEFAULT_GOOGLE_TOKEN_URL);
    let userinfo_url = cfg
        .google_userinfo_url
        .as_deref()
        .unwrap_or(DEFAULT_GOOGLE_USERINFO_URL);
    let redirect_uri = cfg.redirect_uri();

    let client = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .map_err(|_| OAuthError::Config)?;

    tracing::info!(
        provider = "google",
        operation = "oauth_exchange",
        outcome = "start",
        "lepton_auth.oauth.exchange"
    );

    let access_token = fetch_access_token(
        &client,
        token_url,
        code,
        client_id,
        client_secret,
        &redirect_uri,
        code_verifier,
    )
    .await?;
    let (sub, email_hint, name_hint) = fetch_userinfo(&client, userinfo_url, &access_token).await?;
    drop(access_token);

    tracing::info!(
        provider = "google",
        operation = "oauth_exchange",
        outcome = "ok",
        "lepton_auth.oauth.exchange"
    );
    Ok((sub, email_hint, name_hint))
}

async fn fetch_access_token(
    client: &reqwest::Client,
    token_url: &str,
    code: &str,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> Result<String, OAuthError> {
    let token_resp = client
        .post(token_url)
        .form(&[
            ("code", code),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", redirect_uri),
            ("grant_type", "authorization_code"),
            ("code_verifier", code_verifier),
        ])
        .send()
        .await
        .map_err(|_| provider_fail())?;

    if !token_resp.status().is_success() {
        return Err(provider_fail());
    }

    let token: TokenResponse = token_resp.json().await.map_err(|_| provider_fail())?;
    token
        .access_token
        .filter(|s| !s.is_empty())
        .ok_or_else(provider_fail)
}

async fn fetch_userinfo(
    client: &reqwest::Client,
    userinfo_url: &str,
    access_token: &str,
) -> Result<(String, Option<String>, Option<String>), OAuthError> {
    let userinfo_resp = client
        .get(userinfo_url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|_| provider_fail())?;

    if !userinfo_resp.status().is_success() {
        return Err(provider_fail());
    }

    let info: UserInfoResponse = userinfo_resp.json().await.map_err(|_| provider_fail())?;
    let sub = info
        .sub
        .filter(|s| !s.is_empty())
        .ok_or_else(provider_fail)?;
    let email_hint = info.email.filter(|s| !s.is_empty());
    let name_hint = info.name.filter(|s| !s.is_empty());
    Ok((sub, email_hint, name_hint))
}

fn provider_fail() -> OAuthError {
    tracing::warn!(
        provider = "google",
        operation = "oauth_exchange",
        outcome = "provider",
        "lepton_auth.oauth.exchange"
    );
    OAuthError::Provider
}

#[cfg(all(test, feature = "oauth-google"))]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_cfg(token_url: String, userinfo_url: String) -> OAuthClientConfig {
        OAuthClientConfig {
            public_base_url: "http://127.0.0.1:8765".into(),
            redirect_path: "/auth/oauth/callback".into(),
            google_client_id: Some("test-client-id".into()),
            google_client_secret: Some("test-client-secret".into()),
            github_client_id: None,
            github_client_secret: None,
            use_mock_provider: false,
            mock_oidc_issuer_url: None,
            google_token_url: Some(token_url),
            google_userinfo_url: Some(userinfo_url),
            github_token_url: None,
            github_user_url: None,
            github_emails_url: None,
            microsoft_client_id: None,
            microsoft_client_secret: None,
            microsoft_tenant: None,
            microsoft_token_url: None,
            microsoft_userinfo_url: None,
        }
    }

    #[tokio::test]
    async fn google_token_exchange_happy() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("code_verifier=test-verifier"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "ya29.test-access",
                "token_type": "Bearer",
                "expires_in": 3600,
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .and(header("authorization", "Bearer ya29.test-access"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sub": "google-sub-123",
                "email": "user@example.test",
                "name": "Test User",
            })))
            .mount(&server)
            .await;

        let cfg = test_cfg(
            format!("{}/token", server.uri()),
            format!("{}/userinfo", server.uri()),
        );
        let (sub, email, name) = exchange_google_code(&cfg, "auth-code", "test-verifier")
            .await
            .expect("exchange");
        assert_eq!(sub, "google-sub-123");
        assert_eq!(email.as_deref(), Some("user@example.test"));
        assert_eq!(name.as_deref(), Some("Test User"));
    }

    #[tokio::test]
    async fn google_token_auth_failed_sad() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": "invalid_client",
            })))
            .mount(&server)
            .await;

        let cfg = test_cfg(
            format!("{}/token", server.uri()),
            format!("{}/userinfo", server.uri()),
        );
        let err = exchange_google_code(&cfg, "auth-code", "test-verifier")
            .await
            .expect_err("401");
        assert_eq!(err.reason_class(), "oauth_provider");
        assert!(!err.to_string().contains("test-client-secret"));
        assert!(!err.to_string().contains("auth-code"));
    }

    #[tokio::test]
    async fn google_userinfo_missing_sub_sad() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "ya29.test-access",
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "email": "user@example.test",
            })))
            .mount(&server)
            .await;

        let cfg = test_cfg(
            format!("{}/token", server.uri()),
            format!("{}/userinfo", server.uri()),
        );
        let err = exchange_google_code(&cfg, "auth-code", "test-verifier")
            .await
            .expect_err("missing sub");
        assert_eq!(err.reason_class(), "oauth_provider");
    }

    #[tokio::test]
    async fn google_exchange_missing_secret_config_sad() {
        let cfg = OAuthClientConfig {
            public_base_url: "http://127.0.0.1:8765".into(),
            redirect_path: "/auth/oauth/callback".into(),
            google_client_id: Some("id".into()),
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
            microsoft_client_id: None,
            microsoft_client_secret: None,
            microsoft_tenant: None,
            microsoft_token_url: None,
            microsoft_userinfo_url: None,
        };
        let err = exchange_google_code(&cfg, "code", "test-verifier")
            .await
            .expect_err("config");
        assert_eq!(err.reason_class(), "oauth_config");
    }
}
