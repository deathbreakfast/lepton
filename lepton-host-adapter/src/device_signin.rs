//! The two HTTP routes of device sign-in (RFC 8628) for a host to mount.
//!
//! A device that can't show a browser signs in like this:
//!
//! 1. It posts to [`DEVICE_CODE_PATH`] (`/auth/device/code`) with its `client_id`, a
//!    `device_name` and the `scope` it wants, and gets a `device_code`, a `user_code` such as
//!    `WDJB-MJHT`, the page to open, and how often to poll.
//! 2. The person opens the page, types the user code, picks one of their own service users and
//!    approves (`lepton_auth::device_signin::approve_device`).
//! 3. The device posts to [`DEVICE_TOKEN_PATH`] (`/auth/device/token`) with
//!    `grant_type=urn:ietf:params:oauth:grant-type:device_code` and its `device_code` every
//!    `interval` seconds. Until the person approves it gets the RFC 8628 errors
//!    (`authorization_pending`, `slow_down`, `expired_token`, `access_denied`); then it gets a
//!    service user token, once.
//!
//! Both routes accept a form body (the RFC's encoding) or JSON, and answer in JSON. The work
//! itself is done by a [`DeviceSigninFlow`]; `lepton_auth::device_signin::LeptonDeviceFlow`
//! is Lepton's. lepton-auth depends on this crate, so the routes take the flow as a trait
//! object instead of calling it directly.
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use axum::Router;
//! use higgs_core::HiggsValenceFactory;
//! use lepton_host_adapter::device_signin::{device_signin_routes, DeviceSigninConfig, DeviceSigninFlow};
//!
//! fn app(factory: Arc<dyn HiggsValenceFactory>, flow: Arc<dyn DeviceSigninFlow>) -> Router {
//!     Router::new().merge(device_signin_routes(DeviceSigninConfig {
//!         flow,
//!         factory,
//!         verification_uri: "https://lepton.example.com/auth/device".into(),
//!         trust_forwarded_for: true,
//!     }))
//! }
//! ```
//!
//! # The System lookup
//!
//! Neither route has a signed-in caller: the device is who the request is about. Like
//! [`bearer_middleware`](crate::bearer_middleware), each route opens one Valence as
//! `Actor::System { operation: "lepton_device_signin" }` and hands it to the flow, which uses
//! it only to create and look up the pending request by its device code. The token is minted
//! on a Valence opened as the approved service user.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    extract::{ConnectInfo, FromRequest, Request},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Extension, Form, Json, Router,
};
use higgs_core::HiggsValenceFactory;
use lepton_identity::tokens::ApiScope;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use valence::{Actor, Valence};

/// Where a device asks for a device code.
pub const DEVICE_CODE_PATH: &str = "/auth/device/code";

/// Where a device polls for its token.
pub const DEVICE_TOKEN_PATH: &str = "/auth/device/token";

/// The `grant_type` a poll must carry.
pub const DEVICE_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

const MAX_USER_AGENT: usize = 255;

/// What a device asks for when it starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceStartRequest {
    /// The app asking, such as `uf CLI 0.4` (the request's `client_id`).
    pub client: String,
    /// What the device calls itself, such as `mei-laptop`. Defaults to the client.
    pub device_name: String,
    /// The scopes it asks for, as sent (the request's space-separated `scope`).
    pub scopes: Vec<String>,
    /// The address the request came from.
    pub asked_from: Option<String>,
    /// The request's `User-Agent`, cut to 255 characters.
    pub user_agent: Option<String>,
}

/// The codes a started device gets.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceStartGrant {
    /// The secret the device polls with. Shown once.
    pub device_code: String,
    /// The `XXXX-XXXX` code the person types.
    pub user_code: String,
    /// Seconds until both codes stop working.
    pub expires_in: u64,
    /// Seconds the device waits between polls.
    pub interval: u64,
}

impl std::fmt::Debug for DeviceStartGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceStartGrant")
            .field("device_code", &"<redacted>")
            .field("user_code", &self.user_code)
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .finish()
    }
}

/// Why a start was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceStartError {
    /// A missing or too long `client_id` or `device_name` (`invalid_request`).
    InvalidRequest,
    /// A scope the host doesn't offer (`invalid_scope`).
    InvalidScope,
    /// Storage or host configuration failed (`server_error`).
    ServerError,
}

impl DeviceStartError {
    /// The OAuth error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidScope => "invalid_scope",
            Self::ServerError => "server_error",
        }
    }
}

/// The token a device collects once it's approved.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceTokenGrant {
    /// The service user token (`lptk_…`). Shown once.
    pub access_token: String,
    /// Seconds until the token expires.
    pub expires_in: u64,
    /// The APIs the token may call.
    pub scopes: Vec<ApiScope>,
}

impl std::fmt::Debug for DeviceTokenGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceTokenGrant")
            .field("access_token", &"<redacted>")
            .field("expires_in", &self.expires_in)
            .field("scopes", &self.scopes)
            .finish()
    }
}

/// Why a poll got no token (RFC 8628 section 3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevicePollError {
    /// The person hasn't approved or denied yet.
    AuthorizationPending,
    /// The device polled sooner than `interval`.
    SlowDown,
    /// The codes expired before anyone approved them.
    ExpiredToken,
    /// The person denied it, or the service user it was approved as can't act.
    AccessDenied,
    /// An unknown device code, or one whose token was already collected.
    InvalidGrant,
    /// Storage failed.
    ServerError,
}

impl DevicePollError {
    /// The OAuth error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizationPending => "authorization_pending",
            Self::SlowDown => "slow_down",
            Self::ExpiredToken => "expired_token",
            Self::AccessDenied => "access_denied",
            Self::InvalidGrant => "invalid_grant",
            Self::ServerError => "server_error",
        }
    }
}

/// The work behind the two routes. `lepton_auth::device_signin::LeptonDeviceFlow` is Lepton's.
#[async_trait]
pub trait DeviceSigninFlow: Send + Sync {
    /// Create a pending request. `lookup` is the routes' System handle.
    async fn start(
        &self,
        lookup: &Valence,
        request: DeviceStartRequest,
    ) -> Result<DeviceStartGrant, DeviceStartError>;

    /// Answer one poll. `lookup` is the routes' System handle.
    async fn poll(
        &self,
        lookup: &Valence,
        device_code: &str,
    ) -> Result<DeviceTokenGrant, DevicePollError>;
}

/// What [`device_signin_routes`] needs.
#[derive(Clone)]
pub struct DeviceSigninConfig {
    /// Does the work.
    pub flow: Arc<dyn DeviceSigninFlow>,
    /// Builds the System lookup handle (`higgs.valence_factory()`).
    pub factory: Arc<dyn HiggsValenceFactory>,
    /// The approval page's full URL, which the device shows the person.
    pub verification_uri: String,
    /// Take the request's address from the first `X-Forwarded-For` entry. Turn it on only
    /// behind a proxy that sets the header; otherwise the peer address is used, when the host
    /// serves with `into_make_service_with_connect_info`.
    pub trust_forwarded_for: bool,
}

/// The `POST /auth/device/code` and `POST /auth/device/token` routes.
pub fn device_signin_routes<S>(config: DeviceSigninConfig) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::<S>::new()
        .route(DEVICE_CODE_PATH, post(start_handler))
        .route(DEVICE_TOKEN_PATH, post(token_handler))
        .layer(Extension(Arc::new(config)))
}

#[derive(Debug, Deserialize)]
struct StartBody {
    client_id: Option<String>,
    device_name: Option<String>,
    scope: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenBody {
    grant_type: Option<String>,
    device_code: Option<String>,
}

#[derive(Serialize)]
struct StartResponse<'a> {
    device_code: &'a str,
    user_code: &'a str,
    verification_uri: &'a str,
    verification_uri_complete: String,
    expires_in: u64,
    interval: u64,
}

#[derive(Serialize)]
struct TokenResponse<'a> {
    access_token: &'a str,
    token_type: &'static str,
    expires_in: u64,
    scope: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
}

/// Parse a form body, or JSON when the request says so.
async fn body<T: DeserializeOwned + 'static>(req: Request) -> Option<T> {
    let json = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"));
    if json {
        Json::<T>::from_request(req, &())
            .await
            .ok()
            .map(|Json(t)| t)
    } else {
        Form::<T>::from_request(req, &())
            .await
            .ok()
            .map(|Form(t)| t)
    }
}

fn no_store(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

fn error(code: &'static str) -> Response {
    let status = if code == "server_error" {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::BAD_REQUEST
    };
    no_store((status, Json(ErrorResponse { error: code })).into_response())
}

fn lookup_valence(factory: &dyn HiggsValenceFactory) -> Option<Valence> {
    let actor = Actor::System {
        operation: "lepton_device_signin".to_string(),
    };
    let actor_json = serde_json::to_value(&actor).ok()?;
    factory.build(&actor_json).ok()
}

fn asked_from(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    trust_forwarded_for: bool,
) -> Option<String> {
    let forwarded = trust_forwarded_for
        .then(|| headers.get("x-forwarded-for")?.to_str().ok())
        .flatten()
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string);
    forwarded.or_else(|| peer.map(|p| p.ip().to_string()))
}

fn user_agent(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::USER_AGENT)?.to_str().ok()?.trim();
    (!raw.is_empty()).then(|| raw.chars().take(MAX_USER_AGENT).collect())
}

async fn start_handler(
    Extension(config): Extension<Arc<DeviceSigninConfig>>,
    req: Request,
) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| *addr);
    let asked_from = asked_from(req.headers(), peer, config.trust_forwarded_for);
    let user_agent = user_agent(req.headers());
    let Some(form) = body::<StartBody>(req).await else {
        return error(DeviceStartError::InvalidRequest.as_str());
    };
    let client = form.client_id.unwrap_or_default().trim().to_string();
    let device_name = form
        .device_name
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| client.clone());
    let request = DeviceStartRequest {
        client,
        device_name,
        scopes: form
            .scope
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_string)
            .collect(),
        asked_from,
        user_agent,
    };
    let Some(lookup) = lookup_valence(config.factory.as_ref()) else {
        tracing::warn!(target: "lepton.device_signin", "device code: valence factory build failed");
        return error(DeviceStartError::ServerError.as_str());
    };
    match config.flow.start(&lookup, request).await {
        Ok(grant) => no_store(
            Json(StartResponse {
                device_code: &grant.device_code,
                user_code: &grant.user_code,
                verification_uri: &config.verification_uri,
                verification_uri_complete: format!(
                    "{}?user_code={}",
                    config.verification_uri, grant.user_code
                ),
                expires_in: grant.expires_in,
                interval: grant.interval,
            })
            .into_response(),
        ),
        Err(e) => error(e.as_str()),
    }
}

async fn token_handler(
    Extension(config): Extension<Arc<DeviceSigninConfig>>,
    req: Request,
) -> Response {
    let Some(form) = body::<TokenBody>(req).await else {
        return error("invalid_request");
    };
    if form.grant_type.as_deref() != Some(DEVICE_CODE_GRANT_TYPE) {
        return error("unsupported_grant_type");
    }
    let Some(device_code) = form.device_code.filter(|c| !c.trim().is_empty()) else {
        return error("invalid_request");
    };
    let Some(lookup) = lookup_valence(config.factory.as_ref()) else {
        tracing::warn!(target: "lepton.device_signin", "device token: valence factory build failed");
        return error(DevicePollError::ServerError.as_str());
    };
    match config.flow.poll(&lookup, &device_code).await {
        Ok(grant) => no_store(
            Json(TokenResponse {
                access_token: &grant.access_token,
                token_type: "Bearer",
                expires_in: grant.expires_in,
                scope: grant
                    .scopes
                    .iter()
                    .map(ApiScope::as_str)
                    .collect::<Vec<_>>()
                    .join(" "),
            })
            .into_response(),
        ),
        Err(e) => error(e.as_str()),
    }
}

#[cfg(test)]
mod tests {
    use axum::body::{to_bytes, Body};
    use axum::http::Request as HttpRequest;
    use tower::ServiceExt;

    use super::*;

    struct SystemOnlyFactory;

    impl HiggsValenceFactory for SystemOnlyFactory {
        fn build(&self, _actor_json: &serde_json::Value) -> anyhow::Result<Valence> {
            anyhow::bail!("no storage in this test")
        }
    }

    struct Unused;

    #[async_trait]
    impl DeviceSigninFlow for Unused {
        async fn start(
            &self,
            _lookup: &Valence,
            _request: DeviceStartRequest,
        ) -> Result<DeviceStartGrant, DeviceStartError> {
            Err(DeviceStartError::ServerError)
        }

        async fn poll(
            &self,
            _lookup: &Valence,
            _device_code: &str,
        ) -> Result<DeviceTokenGrant, DevicePollError> {
            Err(DevicePollError::ServerError)
        }
    }

    fn app() -> Router {
        device_signin_routes(DeviceSigninConfig {
            flow: Arc::new(Unused),
            factory: Arc::new(SystemOnlyFactory),
            verification_uri: "https://lepton.example.com/auth/device".into(),
            trust_forwarded_for: false,
        })
    }

    async fn post_form(path: &str, body: &str) -> (StatusCode, String) {
        let response = app()
            .oneshot(
                HttpRequest::post(path)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body.to_string()))
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 4096).await.expect("body");
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    #[tokio::test]
    async fn wrong_grant_type_refused_sad() {
        let (status, body) =
            post_form(DEVICE_TOKEN_PATH, "grant_type=password&device_code=x").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("unsupported_grant_type"), "{body}");
    }

    #[tokio::test]
    async fn missing_device_code_refused_sad() {
        let (status, body) = post_form(
            DEVICE_TOKEN_PATH,
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("invalid_request"), "{body}");
    }

    #[tokio::test]
    async fn factory_failure_is_server_error_sad() {
        let (status, body) = post_form(DEVICE_CODE_PATH, "client_id=uf").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.contains("server_error"), "{body}");
    }

    #[test]
    fn asked_from_prefers_trusted_forwarded_for_happy() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.24, 10.0.0.1"),
        );
        let peer: SocketAddr = "10.0.0.9:443".parse().expect("addr");
        assert_eq!(
            asked_from(&headers, Some(peer), true).as_deref(),
            Some("203.0.113.24")
        );
        assert_eq!(
            asked_from(&headers, Some(peer), false).as_deref(),
            Some("10.0.0.9")
        );
        assert_eq!(asked_from(&HeaderMap::new(), None, true), None);
    }

    #[test]
    fn grants_redact_secrets_happy() {
        let grant = DeviceTokenGrant {
            access_token: "lptk_secret".into(),
            expires_in: 1,
            scopes: vec![],
        };
        assert!(!format!("{grant:?}").contains("lptk_secret"));
        let start = DeviceStartGrant {
            device_code: "lpdc_secret".into(),
            user_code: "WDJB-MJHT".into(),
            expires_in: 600,
            interval: 5,
        };
        assert!(!format!("{start:?}").contains("lpdc_secret"));
    }
}
