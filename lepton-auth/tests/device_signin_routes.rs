//! Device sign-in over HTTP: the two routes from `lepton_host_adapter::device_signin` with
//! Lepton's flow, then the collected token on a `require_scope` route.
//!
//! It lives here rather than in lepton-host-adapter because the flow is lepton-auth's, and
//! lepton-auth depends on the host adapter.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

#[path = "support/service_users.rs"]
mod service_users_support;

use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::Extension;
use axum::http::{header, Request, StatusCode};
use axum::routing::get;
use axum::{middleware, Router};
use higgs::HiggsValenceFactory;
use lepton_auth::device_signin::{
    approve_device_without_step_up as approve_device, lookup_device_request, ActAs, ApproveDevice,
    LeptonDeviceFlow,
};
use lepton_host_adapter::device_signin::{
    device_signin_routes, DeviceSigninConfig, DEVICE_CODE_PATH, DEVICE_TOKEN_PATH,
};
use lepton_host_adapter::{bearer_middleware, require_scope, BearerValence};
use lepton_identity::tokens::{ApiScope, TokenLifetime};
use service_users_support::{
    install_test_gate, install_test_scopes, seed_service_user, MAGNON_READ,
};
use support::system_valence;
use tower::ServiceExt;
use valence::{Actor, Valence};

/// Opens every handle on the test's one store.
struct SharedStore(Valence);

impl HiggsValenceFactory for SharedStore {
    fn build(&self, actor_json: &serde_json::Value) -> anyhow::Result<Valence> {
        let actor: Actor = serde_json::from_value(actor_json.clone())?;
        Ok(self.0.with_actor(actor))
    }
}

async fn whoami(Extension(BearerValence(valence)): Extension<BearerValence>) -> String {
    serde_json::to_string(valence.actor()).unwrap()
}

fn app(sys: &Valence) -> Router {
    let factory: Arc<dyn HiggsValenceFactory> = Arc::new(SharedStore(sys.clone()));
    let scope = |raw: &str| ApiScope::parse(raw).unwrap();
    let api = Router::new()
        .route("/api/magnon/tasks", get(whoami))
        .route_layer(middleware::from_fn_with_state(
            scope("magnon:read"),
            require_scope,
        ))
        .merge(
            Router::new()
                .route("/api/spectra/metrics", get(whoami))
                .route_layer(middleware::from_fn_with_state(
                    scope("spectra:read"),
                    require_scope,
                )),
        )
        .layer(middleware::from_fn_with_state(
            Arc::clone(&factory),
            bearer_middleware,
        ));
    Router::new()
        .merge(device_signin_routes(DeviceSigninConfig {
            flow: Arc::new(LeptonDeviceFlow::with_poll_interval(Duration::ZERO)),
            factory,
            verification_uri: "https://lepton.example.com/auth/device".into(),
            trust_forwarded_for: true,
        }))
        .merge(api)
}

async fn send(app: &Router, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, String) {
    let response = app.clone().oneshot(req).await.expect("response");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body");
    (
        status,
        headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

fn form(path: &str, body: &str) -> Request<Body> {
    Request::post(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("x-forwarded-for", "203.0.113.24, 10.0.0.1")
        .header(header::USER_AGENT, "uf/0.4 (Linux)")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn json(text: &str) -> serde_json::Value {
    serde_json::from_str(text).expect("json body")
}

#[tokio::test]
async fn device_signs_in_over_http_and_calls_a_scoped_route_happy() {
    install_test_gate();
    install_test_scopes();
    let sys = system_valence("device_routes").await;
    let (mei, id, _) = seed_service_user(&sys, "maker-dev-http", "dev-http").await;
    let app = app(&sys);

    let (status, headers, body) = send(
        &app,
        form(
            DEVICE_CODE_PATH,
            "client_id=uf+CLI+0.4&device_name=mei-laptop&scope=magnon%3Aread",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
    let started = json(&body);
    let device_code = started["device_code"].as_str().unwrap().to_string();
    let user_code = started["user_code"].as_str().unwrap().to_string();
    assert_eq!(started["expires_in"], 600);
    assert_eq!(started["interval"], 1);
    assert_eq!(
        started["verification_uri_complete"],
        format!("https://lepton.example.com/auth/device?user_code={user_code}")
    );

    let poll_body = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code={device_code}"
    );
    let (status, _, body) = send(&app, form(DEVICE_TOKEN_PATH, &poll_body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json(&body)["error"], "authorization_pending");

    let request = lookup_device_request(&mei, &user_code)
        .await
        .expect("lookup");
    assert_eq!(request.asked_from.as_deref(), Some("203.0.113.24"));
    assert_eq!(request.user_agent.as_deref(), Some("uf/0.4 (Linux)"));
    approve_device(
        &mei,
        ApproveDevice {
            user_code: &user_code,
            act_as: ActAs::Existing(&id),
            scopes: &MAGNON_READ,
            lifetime: TokenLifetime::Days90,
        },
    )
    .await
    .expect("approve");

    // JSON works as well as a form.
    let (status, headers, body) = send(
        &app,
        Request::post(DEVICE_TOKEN_PATH)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code,
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
    let granted = json(&body);
    assert_eq!(granted["token_type"], "Bearer");
    assert_eq!(granted["scope"], "magnon:read");
    assert!(granted["expires_in"].as_u64().unwrap() > 89 * 86_400);
    let token = granted["access_token"].as_str().unwrap().to_string();

    let bearer = |path: &str| {
        Request::get(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    };
    let (status, _, body) = send(&app, bearer("/api/magnon/tasks")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        serde_json::to_string(&id.actor()).unwrap(),
        "acts as the service user"
    );
    let (status, _, _) = send(&app, bearer("/api/spectra/metrics")).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a scope the approver didn't tick"
    );

    let (status, _, body) = send(&app, form(DEVICE_TOKEN_PATH, &poll_body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json(&body)["error"], "invalid_grant", "works once");
}

#[tokio::test]
async fn bad_start_requests_refused_sad() {
    install_test_gate();
    install_test_scopes();
    let sys = system_valence("device_routes_bad").await;
    let app = app(&sys);
    let (status, _, body) = send(&app, form(DEVICE_CODE_PATH, "device_name=x")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json(&body)["error"], "invalid_request");
    let (status, _, body) = send(
        &app,
        form(DEVICE_CODE_PATH, "client_id=uf&scope=billing%3Awrite"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json(&body)["error"], "invalid_scope");
    let (status, _, body) = send(
        &app,
        form(
            DEVICE_TOKEN_PATH,
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=lpdc_x",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json(&body)["error"], "invalid_grant");
}
