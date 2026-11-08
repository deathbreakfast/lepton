//! Live GitHub OAuth authorization-code exchange (token + user / emails).

use serde::Deserialize;
use std::time::Duration;

use super::api::OAuthClientConfig;
use super::error::OAuthError;

/// Default GitHub OAuth token endpoint.
pub const DEFAULT_GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
/// Default GitHub authenticated user endpoint.
pub const DEFAULT_GITHUB_USER_URL: &str = "https://api.github.com/user";
/// Default GitHub user emails endpoint.
pub const DEFAULT_GITHUB_EMAILS_URL: &str = "https://api.github.com/user/emails";

const HTTP_TIMEOUT: Duration = Duration::from_secs(15);
const USER_AGENT: &str = "lepton-auth";

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UserResponse {
    id: Option<u64>,
    email: Option<String>,
    name: Option<String>,
    login: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EmailRow {
    email: Option<String>,
    primary: Option<bool>,
    verified: Option<bool>,
}

/// Exchange an authorization `code` for `(provider_subject, email_hint, name_hint)`.
///
/// Subject is the decimal string of the GitHub numeric user `id`.
/// Email comes from `/user` when present; otherwise the primary verified
/// address from `/user/emails`. Name prefers `name`, then `login`.
///
/// # Errors
///
/// [`OAuthError::Config`] when client id/secret missing.
/// [`OAuthError::Provider`] on HTTP / parse / missing `id` (no secrets in errors).
pub(super) async fn exchange_github_code(
    cfg: &OAuthClientConfig,
    code: &str,
    code_verifier: &str,
) -> Result<(String, Option<String>, Option<String>), OAuthError> {
    let client_id = cfg
        .github_client_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or(OAuthError::Config)?;
    let client_secret = cfg
        .github_client_secret
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or(OAuthError::Config)?;
    let code = code.trim();
    if code.is_empty() {
        return Err(OAuthError::Provider);
    }

    let token_url = cfg
        .github_token_url
        .as_deref()
        .unwrap_or(DEFAULT_GITHUB_TOKEN_URL);
    let user_url = cfg
        .github_user_url
        .as_deref()
        .unwrap_or(DEFAULT_GITHUB_USER_URL);
    let emails_url = cfg
        .github_emails_url
        .as_deref()
        .unwrap_or(DEFAULT_GITHUB_EMAILS_URL);
    let redirect_uri = cfg.redirect_uri();

    let client = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .map_err(|_| OAuthError::Config)?;

    tracing::info!(
        provider = "github",
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
    let (subject, email_hint, name_hint) =
        fetch_user_and_email(&client, user_url, emails_url, &access_token).await?;
    drop(access_token);

    tracing::info!(
        provider = "github",
        operation = "oauth_exchange",
        outcome = "ok",
        "lepton_auth.oauth.exchange"
    );
    Ok((subject, email_hint, name_hint))
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
        .header("Accept", "application/json")
        .header("User-Agent", USER_AGENT)
        .form(&[
            ("code", code),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", redirect_uri),
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

async fn fetch_user_and_email(
    client: &reqwest::Client,
    user_url: &str,
    emails_url: &str,
    access_token: &str,
) -> Result<(String, Option<String>, Option<String>), OAuthError> {
    let user_resp = client
        .get(user_url)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", USER_AGENT)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|_| provider_fail())?;

    if !user_resp.status().is_success() {
        return Err(provider_fail());
    }

    let user: UserResponse = user_resp.json().await.map_err(|_| provider_fail())?;
    let subject = user
        .id
        .map(|id| id.to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(provider_fail)?;
    let mut email_hint = user.email.filter(|s| !s.is_empty());
    if email_hint.is_none() {
        email_hint = fetch_primary_email(client, emails_url, access_token).await?;
    }
    let name_hint = user
        .name
        .filter(|s| !s.is_empty())
        .or_else(|| user.login.filter(|s| !s.is_empty()));
    Ok((subject, email_hint, name_hint))
}

async fn fetch_primary_email(
    client: &reqwest::Client,
    emails_url: &str,
    access_token: &str,
) -> Result<Option<String>, OAuthError> {
    let emails_resp = client
        .get(emails_url)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", USER_AGENT)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|_| provider_fail())?;

    if !emails_resp.status().is_success() {
        return Err(provider_fail());
    }

    let rows: Vec<EmailRow> = emails_resp.json().await.map_err(|_| provider_fail())?;
    let primary = rows.into_iter().find(|r| {
        r.primary.unwrap_or(false)
            && r.verified.unwrap_or(false)
            && r.email.as_ref().is_some_and(|e| !e.is_empty())
    });
    Ok(primary.and_then(|r| r.email))
}

fn provider_fail() -> OAuthError {
    tracing::warn!(
        provider = "github",
        operation = "oauth_exchange",
        outcome = "provider",
        "lepton_auth.oauth.exchange"
    );
    OAuthError::Provider
}

#[cfg(all(test, feature = "oauth-github"))]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_cfg(token_url: String, user_url: String, emails_url: String) -> OAuthClientConfig {
        OAuthClientConfig {
            public_base_url: "http://127.0.0.1:8765".into(),
            redirect_path: "/auth/oauth/callback".into(),
            google_client_id: None,
            google_client_secret: None,
            github_client_id: Some("test-client-id".into()),
            github_client_secret: Some("test-client-secret".into()),
            use_mock_provider: false,
            mock_oidc_issuer_url: None,
            google_token_url: None,
            google_userinfo_url: None,
            github_token_url: Some(token_url),
            github_user_url: Some(user_url),
            github_emails_url: Some(emails_url),
            microsoft_client_id: None,
            microsoft_client_secret: None,
            microsoft_tenant: None,
            microsoft_token_url: None,
            microsoft_userinfo_url: None,
        }
    }

    #[tokio::test]
    async fn github_token_exchange_happy() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/login/oauth/access_token"))
            .and(header("accept", "application/json"))
            .and(body_string_contains("code_verifier=test-verifier"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "gho_test_access",
                "token_type": "bearer",
                "scope": "read:user,user:email",
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/user"))
            .and(header("authorization", "Bearer gho_test_access"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 424_242,
                "login": "octocat",
                "email": "octocat@example.test",
            })))
            .mount(&server)
            .await;

        let cfg = test_cfg(
            format!("{}/login/oauth/access_token", server.uri()),
            format!("{}/user", server.uri()),
            format!("{}/user/emails", server.uri()),
        );
        let (sub, email, _name) = exchange_github_code(&cfg, "auth-code", "test-verifier")
            .await
            .expect("exchange");
        assert_eq!(sub, "424242");
        assert_eq!(email.as_deref(), Some("octocat@example.test"));
    }

    #[tokio::test]
    async fn github_email_from_emails_endpoint_happy() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/login/oauth/access_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "gho_test_access",
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/user"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 99,
                "login": "octocat",
                "email": null,
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/user/emails"))
            .and(header("authorization", "Bearer gho_test_access"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "email": "secondary@example.test",
                    "primary": false,
                    "verified": true,
                },
                {
                    "email": "primary@example.test",
                    "primary": true,
                    "verified": true,
                }
            ])))
            .mount(&server)
            .await;

        let cfg = test_cfg(
            format!("{}/login/oauth/access_token", server.uri()),
            format!("{}/user", server.uri()),
            format!("{}/user/emails", server.uri()),
        );
        let (sub, email, _name) = exchange_github_code(&cfg, "auth-code", "test-verifier")
            .await
            .expect("exchange");
        assert_eq!(sub, "99");
        assert_eq!(email.as_deref(), Some("primary@example.test"));
    }

    #[tokio::test]
    async fn github_token_auth_failed_sad() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/login/oauth/access_token"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": "bad_verification_code",
            })))
            .mount(&server)
            .await;

        let cfg = test_cfg(
            format!("{}/login/oauth/access_token", server.uri()),
            format!("{}/user", server.uri()),
            format!("{}/user/emails", server.uri()),
        );
        let err = exchange_github_code(&cfg, "auth-code", "test-verifier")
            .await
            .expect_err("401");
        assert_eq!(err.reason_class(), "oauth_provider");
        assert!(!err.to_string().contains("test-client-secret"));
        assert!(!err.to_string().contains("auth-code"));
    }

    #[tokio::test]
    async fn github_user_missing_id_sad() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/login/oauth/access_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "gho_test_access",
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/user"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "login": "octocat",
                "email": "octocat@example.test",
            })))
            .mount(&server)
            .await;

        let cfg = test_cfg(
            format!("{}/login/oauth/access_token", server.uri()),
            format!("{}/user", server.uri()),
            format!("{}/user/emails", server.uri()),
        );
        let err = exchange_github_code(&cfg, "auth-code", "test-verifier")
            .await
            .expect_err("missing id");
        assert_eq!(err.reason_class(), "oauth_provider");
    }

    #[tokio::test]
    async fn github_exchange_missing_secret_config_sad() {
        let cfg = OAuthClientConfig {
            public_base_url: "http://127.0.0.1:8765".into(),
            redirect_path: "/auth/oauth/callback".into(),
            google_client_id: None,
            google_client_secret: None,
            github_client_id: Some("id".into()),
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
        let err = exchange_github_code(&cfg, "code", "test-verifier")
            .await
            .expect_err("config");
        assert_eq!(err.reason_class(), "oauth_config");
    }
}
