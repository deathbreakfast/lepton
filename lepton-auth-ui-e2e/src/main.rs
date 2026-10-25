//! Axum + Leptos host for `lepton-auth-ui` Playwright.

#![allow(clippy::print_stdout, missing_docs)]

use std::sync::Arc;

use axum::extract::FromRef;
use axum::middleware::from_fn;
use axum::routing::post;
use axum::{Extension, Router};
use axum_login::AuthManagerLayerBuilder;
use lepton_auth::services::provide_auth_services;
use lepton_auth_ui_e2e::app::{shell, App};
use lepton_auth_ui_e2e::boot::{boot_platform, lab_env};
use lepton_auth_ui_e2e::seed::seed_data;
use lepton_host_adapter::session_snapshot_middleware;
use leptos::prelude::*;
use leptos_axum::{generate_route_list, LeptosRoutes};
use tower_sessions::{MemoryStore, SessionManagerLayer};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    if std::env::var_os("VALENCE_OWNERSHIP_UNIFIED_FETCH").is_none() {
        std::env::set_var("VALENCE_OWNERSHIP_UNIFIED_FETCH", "0");
    }
    if std::env::var_os("VALENCE_OWNERSHIP_COLOCATE").is_none() {
        std::env::set_var("VALENCE_OWNERSHIP_COLOCATE", "0");
    }

    // Lab mock OIDC on `UF_MOCK_OIDC_URL` (default :5556; reuse if already bound).
    spawn_mock_oidc_sidecar().await?;
    // Lab SMS HTTP sink on `UF_SMS_SINK_URL` (default :8099; reuse if already bound).
    spawn_sms_sink_sidecar().await?;

    let (state, backend, auth_services) = boot_platform()?;
    let leptos_options = state.leptos_options.clone();
    let addr = leptos_options.site_addr;
    let routes = generate_route_list(App);

    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_same_site(tower_sessions::cookie::SameSite::Lax)
        .with_name("session")
        .with_path("/");
    let auth_layer = AuthManagerLayerBuilder::new(backend, session_layer).build();

    let higgs = Arc::clone(&state.higgs);
    let state_shell = state.clone();
    let valence_router = Arc::clone(&state.valence_router);
    let auth_services_for_ctx = Arc::clone(&auth_services);

    let app = Router::new()
        .route(
            "/api/test/seed-data",
            post(seed_data::<lepton_auth_ui_e2e::boot::AppState>),
        )
        .route(
            "/health",
            axum::routing::get(|| async { axum::http::StatusCode::OK }),
        )
        .leptos_routes_with_context(
            &state,
            routes,
            move || {
                provide_context(Arc::clone(&higgs));
                provide_auth_services(Arc::clone(&auth_services_for_ctx));
            },
            move || {
                let options = LeptosOptions::from_ref(&state_shell);
                shell(options)
            },
        )
        .fallback(leptos_axum::file_and_error_handler::<
            lepton_auth_ui_e2e::boot::AppState,
            _,
        >(shell))
        .layer(from_fn(session_snapshot_middleware))
        .layer(auth_layer)
        .layer(Extension(valence_router))
        .with_state(state);

    tracing::info!(%addr, "lepton-auth-ui-e2e listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Start [`lepton_e2e::mock_oidc`] on `UF_MOCK_OIDC_URL` (default
/// `127.0.0.1:5556`), or no-op if already listening.
async fn spawn_mock_oidc_sidecar() -> anyhow::Result<()> {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::Context as _;
    use lepton_e2e::mock_oidc::{serve, CodeStore, DEFAULT_ISSUER};

    let issuer = lab_env("UF_MOCK_OIDC_URL", DEFAULT_ISSUER);
    let issuer = issuer.trim_end_matches('/').to_owned();

    let probe = reqwest::Client::builder()
        .timeout(Duration::from_millis(400))
        .build()?;
    if probe
        .get(format!("{issuer}/.well-known/openid-configuration"))
        .send()
        .await
        .is_ok()
    {
        tracing::info!(issuer = %issuer, "mock OIDC already running");
        return Ok(());
    }

    let addr: SocketAddr = issuer
        .trim_start_matches("http://")
        .parse()
        .with_context(|| format!("UF_MOCK_OIDC_URL {issuer} is not http://host:port"))?;
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            tracing::info!(
                issuer = %issuer,
                "mock OIDC port in use; assuming ready"
            );
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    let served = issuer.clone();
    tokio::spawn(async move {
        if let Err(e) = serve(listener, Arc::new(CodeStore::new()), served).await {
            tracing::error!(error = %e, "mock OIDC serve failed");
        }
    });

    for _ in 0..50 {
        if probe
            .get(format!("{issuer}/.well-known/openid-configuration"))
            .send()
            .await
            .is_ok()
        {
            tracing::info!(issuer = %issuer, "mock OIDC ready");
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::bail!("mock OIDC did not become ready on {issuer}");
}

/// Start [`lepton_e2e::sms_sink`] on `UF_SMS_SINK_URL` (default
/// `127.0.0.1:8099`), or no-op if already listening.
async fn spawn_sms_sink_sidecar() -> anyhow::Result<()> {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::Context as _;
    use lepton_e2e::sms_sink::{serve, MessageStore, DEFAULT_BIND};

    let base = lab_env("UF_SMS_SINK_URL", &format!("http://{DEFAULT_BIND}"));
    let base = base.trim_end_matches('/').to_owned();
    let bind = base.trim_start_matches("http://").to_owned();

    let probe = reqwest::Client::builder()
        .timeout(Duration::from_millis(400))
        .build()?;
    if probe
        .get(format!("{base}/v1/messages"))
        .send()
        .await
        .is_ok()
    {
        tracing::info!(%bind, "SMS sink already running");
        return Ok(());
    }

    let addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("UF_SMS_SINK_URL {base} is not http://host:port"))?;
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            tracing::info!(%bind, "SMS sink port in use; assuming ready");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    tokio::spawn(async move {
        if let Err(e) = serve(listener, Arc::new(MessageStore::new())).await {
            tracing::error!(error = %e, "SMS sink serve failed");
        }
    });

    for _ in 0..50 {
        if probe
            .get(format!("{base}/v1/messages"))
            .send()
            .await
            .is_ok()
        {
            tracing::info!(%bind, "SMS sink ready");
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::bail!("SMS sink did not become ready on {bind}");
}
