//! CI-always HTTP coverage for `lepton_e2e::mock_oidc` (ephemeral bind).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use lepton_e2e::mock_oidc::{serve_for_test, CodeStore};
use serde_json::Value;

async fn spawn_idp() -> (
    String,
    Arc<CodeStore>,
    tokio::task::JoinHandle<std::io::Result<()>>,
) {
    let store = Arc::new(CodeStore::new());
    let (addr, handle) = serve_for_test(SocketAddr::from(([127, 0, 0, 1], 0)), Arc::clone(&store))
        .await
        .expect("bind");
    tokio::time::sleep(Duration::from_millis(20)).await;
    (format!("http://{addr}"), store, handle)
}

#[tokio::test]
async fn mock_oidc_discovery_lists_endpoints_happy() {
    let (base, _store, handle) = spawn_idp().await;
    let client = reqwest::Client::new();
    let doc: Value = client
        .get(format!("{base}/.well-known/openid-configuration"))
        .send()
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    assert_eq!(doc["issuer"], base);
    assert_eq!(doc["authorization_endpoint"], format!("{base}/authorize"));
    assert_eq!(doc["token_endpoint"], format!("{base}/token"));
    assert_eq!(doc["userinfo_endpoint"], format!("{base}/userinfo"));
    handle.abort();
}

#[tokio::test]
async fn mock_oidc_authorize_redirects_with_code_happy() {
    let (base, _store, handle) = spawn_idp().await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");
    let res = client
        .get(format!("{base}/authorize"))
        .query(&[
            ("state", "csrf-state"),
            ("redirect_uri", "http://127.0.0.1:3000/auth/oauth/callback"),
            ("provider", "google"),
        ])
        .send()
        .await
        .expect("authorize");
    assert!(res.status().is_redirection());
    let loc = res
        .headers()
        .get("location")
        .expect("location")
        .to_str()
        .expect("str");
    assert!(loc.contains("code=mock-code"));
    assert!(loc.contains("state=csrf-state"));
    handle.abort();
}

#[tokio::test]
async fn mock_oidc_authorize_missing_params_sad() {
    let (base, _store, handle) = spawn_idp().await;
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{base}/authorize"))
        .query(&[("redirect_uri", "http://127.0.0.1:3000/cb")])
        .send()
        .await
        .expect("authorize");
    assert_eq!(res.status(), 400);
    handle.abort();
}

#[tokio::test]
async fn mock_oidc_authorize_disallowed_redirect_sad() {
    let (base, _store, handle) = spawn_idp().await;
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{base}/authorize"))
        .query(&[
            ("state", "s"),
            ("redirect_uri", "https://evil.example/phish"),
            ("provider", "google"),
        ])
        .send()
        .await
        .expect("authorize");
    assert_eq!(res.status(), 400);
    handle.abort();
}

#[tokio::test]
async fn mock_oidc_token_exchanges_code_happy() {
    let (base, store, handle) = spawn_idp().await;
    let code = store.issue_code("google", Some("abc")).expect("issue");
    let client = reqwest::Client::new();
    let res = client
        .post(format!("{base}/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
        ])
        .send()
        .await
        .expect("token");
    assert!(res.status().is_success());
    let body: Value = res.json().await.expect("json");
    assert!(body["access_token"].as_str().unwrap().starts_with("tok-"));

    // Replay fails.
    let res = client
        .post(format!("{base}/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
        ])
        .send()
        .await
        .expect("replay");
    assert_eq!(res.status(), 400);
    handle.abort();
}

#[tokio::test]
async fn mock_oidc_token_bad_grant_sad() {
    let (base, _store, handle) = spawn_idp().await;
    let client = reqwest::Client::new();
    let res = client
        .post(format!("{base}/token"))
        .form(&[("grant_type", "refresh_token"), ("code", "x")])
        .send()
        .await
        .expect("token");
    assert_eq!(res.status(), 400);
    handle.abort();
}

#[tokio::test]
async fn mock_oidc_userinfo_email_happy() {
    let (base, store, handle) = spawn_idp().await;
    let code = store.issue_code("google", Some("user1")).expect("issue");
    let token = store.exchange_code(&code).expect("tok");
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{base}/userinfo"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("userinfo");
    assert!(res.status().is_success());
    let body: Value = res.json().await.expect("json");
    assert_eq!(body["sub"], "mock:google:user1");
    assert_eq!(body["email"], "user1@oauth.mock.test");
    handle.abort();
}

#[tokio::test]
async fn mock_oidc_userinfo_no_email_happy() {
    let (base, store, handle) = spawn_idp().await;
    let code = store.issue_code("google", Some("no-email")).expect("issue");
    let token = store.exchange_code(&code).expect("tok");
    let client = reqwest::Client::new();
    let body: Value = client
        .get(format!("{base}/userinfo"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("userinfo")
        .json()
        .await
        .expect("json");
    assert_eq!(body["sub"], "mock:google:no-email");
    assert!(body.get("email").is_none());
    handle.abort();
}

#[tokio::test]
async fn mock_oidc_userinfo_bad_bearer_sad() {
    let (base, _store, handle) = spawn_idp().await;
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{base}/userinfo"))
        .send()
        .await
        .expect("userinfo");
    assert_eq!(res.status(), 401);
    let res = client
        .get(format!("{base}/userinfo"))
        .bearer_auth("nope")
        .send()
        .await
        .expect("userinfo");
    assert_eq!(res.status(), 401);
    handle.abort();
}

#[tokio::test]
async fn mock_oidc_full_authorize_token_userinfo_chain_happy() {
    let (base, _store, handle) = spawn_idp().await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");
    let res = client
        .get(format!("{base}/authorize"))
        .query(&[
            ("state", "s"),
            ("redirect_uri", "http://127.0.0.1:3000/cb"),
            ("provider", "github"),
            ("code_hint", "chain"),
        ])
        .send()
        .await
        .expect("authorize");
    let loc = res.headers().get("location").unwrap().to_str().unwrap();
    let code = loc
        .split(['?', '&'])
        .find_map(|p| p.strip_prefix("code="))
        .expect("code");
    let token_body: Value = client
        .post(format!("{base}/token"))
        .form(&[("grant_type", "authorization_code"), ("code", code)])
        .send()
        .await
        .expect("token")
        .json()
        .await
        .expect("json");
    let access = token_body["access_token"].as_str().unwrap();
    let user: Value = client
        .get(format!("{base}/userinfo"))
        .bearer_auth(access)
        .send()
        .await
        .expect("userinfo")
        .json()
        .await
        .expect("json");
    assert_eq!(user["sub"], "mock:github:chain");
    assert_eq!(user["email"], "chain@oauth.mock.test");
    handle.abort();
}

#[test]
fn mock_oidc_default_bind_loopback_happy() {
    let addr = lepton_e2e::mock_oidc::default_bind_addr();
    assert!(addr.ip().is_loopback());
    assert_eq!(addr.port(), 5556);
}
