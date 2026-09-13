//! Axum host: axum-login session → `session_snapshot_middleware` → `SessionSnapshot`.
//!
//! Seeds one user in `SQLite` `:memory:`, signs in through `Backend` + axum-login, then
//! reads `Extension<SessionSnapshot>` on a follow-up request (session cookie).
//!
//! ## Command
//! ```bash
//! CARGO_BUILD_JOBS=1 cargo run -p lepton-host-adapter --example axum_session_snapshot --features ssr
//! ```
//!
//! ## Success
//! Stdout prints `axum_session_snapshot: OK — login → SessionSnapshot`.

#![allow(clippy::print_stdout, clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use axum::body::Body;
use axum::extract::Extension;
use axum::http::{header, Request, StatusCode};
use axum::middleware::from_fn;
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_login::{AuthManagerLayerBuilder, AuthnBackend};
use chrono::Utc;
use higgs_core::HiggsValenceFactory;
use higgs_identity::SessionSnapshot;
use lepton_host_adapter::auth::hash_password;
use lepton_host_adapter::{session_snapshot_middleware, AuthSession, Backend, Credentials, User};
use lepton_identity::generated::{
    Account, AccountEmail, AccountMembership, AccountMembershipRole, AccountPlan, AccountStatus,
    User as IdentityUser, UserStatus, UserUserType,
};
use tower::ServiceExt;
use tower_sessions::{MemoryStore, SessionManagerLayer};
use valence::{
    register_backend_logical_names_slices, router_key, Actor, DatabaseBackend, DatabaseRouter,
    Model, RegisterBackendLogicalNamesOptions, SqliteBackend, Valence, SQLITE_ENGINE_ID,
};

/// Thin host factory for this example (same role as host `HiggsValenceFactory` adapters).
struct ExampleHiggsFactory {
    router: Arc<DatabaseRouter>,
    default_backend_key: String,
}

impl HiggsValenceFactory for ExampleHiggsFactory {
    fn build(&self, actor_json: &serde_json::Value) -> anyhow::Result<Valence> {
        let actor: Actor = serde_json::from_value(actor_json.clone())
            .map_err(|e| anyhow::anyhow!("actor deserialize: {e}"))?;
        Valence::builder()
            .database_router(Arc::clone(&self.router))
            .default_backend_key(self.default_backend_key.clone())
            .with_actor(actor)
            .build()
            .map_err(|e| anyhow::anyhow!("{e}"))
    }
}

const DEMO_EMAIL: &str = "demo@example.com";
const DEMO_PASSWORD: &str = "CorrectHorseBattery1!";

#[derive(serde::Deserialize)]
struct LoginBody {
    email: String,
    password: String,
}

async fn bootstrap_router() -> anyhow::Result<(Arc<DatabaseRouter>, String)> {
    let backend: Arc<dyn DatabaseBackend> = Arc::new(SqliteBackend::connect_memory().await?);
    let mut router = DatabaseRouter::new();
    register_backend_logical_names_slices(
        &mut router,
        backend,
        &[&["default"]],
        RegisterBackendLogicalNamesOptions::default(),
    );
    let default_backend_key = router_key("default", SQLITE_ENGINE_ID);
    Ok((Arc::new(router), default_backend_key))
}

#[allow(clippy::too_many_lines)]
async fn seed_user(router: Arc<DatabaseRouter>, default_backend_key: &str) -> anyhow::Result<User> {
    let valence = Valence::builder()
        .database_router(Arc::clone(&router))
        .default_backend_key(default_backend_key.to_owned())
        .with_actor(Actor::System {
            operation: "seed_user".to_string(),
        })
        .build()?;

    let password_hash = hash_password(DEMO_PASSWORD)?;
    let now = Utc::now();
    let user = IdentityUser::new(
        Some(UserUserType::Person),
        Some(password_hash),
        Some(UserStatus::Active),
        None,
        None,
        None,
        None,
        None,
        now,
        now,
    )?;
    let created = IdentityUser::create_used(user, &valence, valence::use_!("create IdentityUser in lepton-host-adapter/examples/axum_session_snapshot.rs; Valence persistence for this feature path; typed store; visible to test harness.")).await?;
    let user_id = created
        .id()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("user missing id"))?;

    let account = Account::new(
        DEMO_EMAIL.to_string(),
        user_id.clone(),
        Some(AccountPlan::Free),
        Some(AccountStatus::Active),
        None,
        None,
        now,
        now,
    )?;
    let account_created = Account::create_used(account, &valence, valence::use_!("create Account in lepton-host-adapter/examples/axum_session_snapshot.rs; Valence persistence for this feature path; typed store; visible to test harness.")).await?;
    let account_id = account_created
        .id()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("account missing id"))?;

    let membership = AccountMembership::new(
        account_id.clone(),
        user_id.clone(),
        AccountMembershipRole::Owner,
        now,
        now,
    )?;
    AccountMembership::create_used(membership, &valence, valence::use_!("create AccountMembership in lepton-host-adapter/examples/axum_session_snapshot.rs; Valence persistence for this feature path; typed store; visible to test harness.")).await?;

    let email_row = AccountEmail::new(
        account_id.clone(),
        DEMO_EMAIL.to_string(),
        Some(now),
        now,
        now,
    )?;
    let email_created = AccountEmail::create_used(email_row, &valence, valence::use_!("create AccountEmail in lepton-host-adapter/examples/axum_session_snapshot.rs; Valence persistence for this feature path; typed store; visible to test harness.")).await?;
    let email_id = email_created
        .id()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("email missing id"))?;

    account_created
        .get_mutable_used(&valence, valence::use_!("get_mutable via axum_session_snapshot.rs; mutable handle for in-place update; typed store; session/service path."))
        .set_primary_email(email_id.clone())
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .set_updated_at(now)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .commit()
        .await?;

    created
        .get_mutable_used(&valence, valence::use_!("get_mutable via axum_session_snapshot.rs; mutable handle for in-place update; typed store; session/service path."))
        .set_primary_email(email_id)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .set_updated_at(now)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .commit()
        .await?;
    let created = IdentityUser::get_used(
        &valence::extract_id_from_record(&user_id).unwrap_or_else(|_| user_id.id().to_string()),
        &valence,
        valence::use_!("get IdentityUser in lepton-host-adapter/examples/axum_session_snapshot.rs; Valence persistence for this feature path; typed store; visible to test harness."),
    )
    .await?
    .ok_or_else(|| anyhow::anyhow!("reload user"))?;
    let factory: Arc<dyn HiggsValenceFactory> = Arc::new(ExampleHiggsFactory {
        router,
        default_backend_key: default_backend_key.to_owned(),
    });
    let backend = Backend::new(factory);
    let session_user = User::from_generated(
        &created,
        DEMO_EMAIL.to_string(),
        true,
        None,
        Some(account_id.to_string()),
        Vec::new(),
    );
    let reloaded = backend
        .get_user(&session_user.session_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("get_user missed freshly seeded user"))?;
    Ok(reloaded)
}

async fn login(mut auth: AuthSession<Backend>, Json(body): Json<LoginBody>) -> StatusCode {
    let creds = Credentials {
        email: body.email,
        password: body.password,
    };
    let Ok(Some(user)) = auth.authenticate(creds).await else {
        return StatusCode::UNAUTHORIZED;
    };
    if auth.login(&user).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    StatusCode::OK
}

async fn whoami(
    auth: AuthSession<Backend>,
    session: Option<Extension<SessionSnapshot>>,
) -> Result<String, StatusCode> {
    if auth.user.is_none() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let Extension(snapshot) = session.ok_or(StatusCode::UNAUTHORIZED)?;
    Ok(format!("ok:{}", snapshot.user_id))
}

fn cookie_from_set_cookie(set_cookie: &str) -> String {
    set_cookie
        .split(';')
        .next()
        .unwrap_or(set_cookie)
        .trim()
        .to_owned()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // SQLite cannot execute Valence's unified ownership `RETURN {…}` get query.
    // Legacy two-trip get works for this in-process smoke (set before any Valence use).
    std::env::set_var("VALENCE_OWNERSHIP_UNIFIED_FETCH", "0");

    let (router, default_backend_key) = bootstrap_router().await?;
    let seeded = seed_user(Arc::clone(&router), &default_backend_key).await?;
    anyhow::ensure!(
        !seeded.session_id.is_empty(),
        "seeded user missing session_id"
    );

    let factory: Arc<dyn HiggsValenceFactory> = Arc::new(ExampleHiggsFactory {
        router,
        default_backend_key,
    });
    let backend = Backend::new(factory);
    // Teaching smoke: in-process MemoryStore over plain HTTP (Secure=false).
    // Production hosts must set Secure / HttpOnly / SameSite — see SECURITY.md.
    let session_layer = SessionManagerLayer::new(MemoryStore::default())
        .with_secure(false)
        .with_http_only(true)
        .with_same_site(tower_sessions::cookie::SameSite::Lax)
        .with_name("session")
        .with_path("/");
    let auth_layer = AuthManagerLayerBuilder::new(backend, session_layer).build();

    // Layer order matches crate rustdoc: snapshot middleware inside auth manager.
    let app = Router::new()
        .route("/login", post(login))
        .route("/whoami", get(whoami))
        .layer(from_fn(session_snapshot_middleware))
        .layer(auth_layer);

    let anon = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/whoami")
                .body(Body::empty())
                .expect("anon request"),
        )
        .await?;
    anyhow::ensure!(anon.status() == StatusCode::UNAUTHORIZED);

    let login_body = serde_json::to_vec(&serde_json::json!({
        "email": DEMO_EMAIL,
        "password": DEMO_PASSWORD,
    }))?;
    let login_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(login_body))
                .expect("login request"),
        )
        .await?;
    anyhow::ensure!(login_res.status() == StatusCode::OK);

    let cookies: Vec<String> = login_res
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(cookie_from_set_cookie)
        .collect();
    anyhow::ensure!(!cookies.is_empty(), "login response missing Set-Cookie");
    let cookie_header = cookies.join("; ");

    let who = app
        .oneshot(
            Request::builder()
                .uri("/whoami")
                .header(header::COOKIE, cookie_header)
                .body(Body::empty())
                .expect("whoami request"),
        )
        .await?;
    if who.status() != StatusCode::OK {
        let status = who.status();
        let body = axum::body::to_bytes(who.into_body(), 4096).await?;
        anyhow::bail!(
            "whoami expected 200, got {status}: {}",
            String::from_utf8_lossy(&body)
        );
    }
    let body = axum::body::to_bytes(who.into_body(), 1024).await?;
    let text = std::str::from_utf8(&body)?;
    anyhow::ensure!(
        text.starts_with("ok:"),
        "whoami body should start with ok:, got {text:?}"
    );

    println!("axum_session_snapshot: OK — login → SessionSnapshot");
    Ok(())
}
