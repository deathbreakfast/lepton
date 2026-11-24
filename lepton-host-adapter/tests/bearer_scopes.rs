//! The bearer layer end to end: a personal token on SQLite `:memory:`, routes guarded by
//! `require_scope`, and the request-scoped Valence the handler gets.
//!
//! ```bash
//! cargo test -p lepton-host-adapter --features ssr --test bearer_scopes
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use axum::body::Body;
use axum::extract::Extension;
use axum::http::{header, Request, StatusCode};
use axum::routing::{get, post};
use axum::{middleware, Router};
use chrono::{Duration, Utc};
use higgs_core::HiggsValenceFactory;
use lepton_host_adapter::{bearer_middleware, require_scope, BearerCaller, BearerValence};
use lepton_identity::generated::{PersonalToken, User, UserStatus, UserUserType};
use lepton_identity::tokens::{scopes_to_json, ApiScope, LeptonToken};
use tower::ServiceExt;
use valence::{
    register_backend_logical_names_slices, router_key, Actor, DatabaseBackend, DatabaseRouter,
    Model, RecordId, RegisterBackendLogicalNamesOptions, SqliteBackend, Valence, SQLITE_ENGINE_ID,
};

struct TestFactory {
    router: Arc<DatabaseRouter>,
    default_backend_key: String,
}

impl HiggsValenceFactory for TestFactory {
    fn build(&self, actor_json: &serde_json::Value) -> anyhow::Result<Valence> {
        let actor: Actor = serde_json::from_value(actor_json.clone())?;
        Ok(Valence::builder()
            .database_router(Arc::clone(&self.router))
            .default_backend_key(self.default_backend_key.clone())
            .with_actor(actor)
            .build()?)
    }
}

struct Harness {
    app: Router,
    system: Valence,
    owner: Valence,
    token: String,
    token_id: String,
}

fn scope(raw: &str) -> ApiScope {
    ApiScope::parse(raw).unwrap()
}

/// Returns the actor the handler's Valence runs as, so the test can check it.
async fn whoami(
    Extension(caller): Extension<BearerCaller>,
    Extension(BearerValence(valence)): Extension<BearerValence>,
) -> String {
    assert_eq!(valence.actor(), &caller.actor());
    serde_json::to_string(valence.actor()).unwrap()
}

async fn harness() -> Harness {
    // SQLite cannot run Valence's unified ownership fetch; same as the crate example.
    std::env::set_var("VALENCE_OWNERSHIP_UNIFIED_FETCH", "0");
    let db: Arc<dyn DatabaseBackend> = Arc::new(SqliteBackend::connect_memory().await.unwrap());
    let mut router = DatabaseRouter::new();
    register_backend_logical_names_slices(
        &mut router,
        db,
        &[&["default"]],
        RegisterBackendLogicalNamesOptions::default(),
    );
    let router = Arc::new(router);
    let key = router_key("default", SQLITE_ENGINE_ID);
    let factory = TestFactory {
        router: Arc::clone(&router),
        default_backend_key: key.clone(),
    };
    let system = factory
        .build(
            &serde_json::to_value(Actor::System {
                operation: "bearer_scopes_test".into(),
            })
            .unwrap(),
        )
        .unwrap();

    let now = Utc::now();
    let user = User::new(
        Some(UserUserType::Person),
        None,
        Some(UserStatus::Active),
        None,
        None,
        None,
        None,
        None,
        now,
        now,
    )
    .unwrap();
    User::upsert("bearer-alice", user, &system, valence::use_!(r"**Test:** the bearer scope suite seeds a **user** so a personal token has a person to act as."))
        .await
        .unwrap();
    let owner = system.with_actor(Actor::User {
        user_id: "bearer-alice".into(),
    });

    let token = LeptonToken::generate();
    let row = PersonalToken::new(
        RecordId::new("user", "bearer-alice"),
        "cli".into(),
        token.hash(),
        scopes_to_json(&[scope("magnon:read")]),
        now + Duration::days(30),
        None,
        None,
        now,
    )
    .unwrap();
    PersonalToken::upsert(token.id(), row, &owner, valence::use_!(r"**Test:** the bearer scope suite saves a **personal token** for the test user, as that user."))
        .await
        .unwrap();

    let factory: Arc<dyn HiggsValenceFactory> = Arc::new(factory);
    let app = Router::new()
        .route("/api/magnon/tasks", get(whoami))
        .route_layer(middleware::from_fn_with_state(
            scope("magnon:read"),
            require_scope,
        ))
        .merge(
            Router::new()
                .route("/api/magnon/tasks/close", post(whoami))
                .route_layer(middleware::from_fn_with_state(
                    scope("magnon:write"),
                    require_scope,
                )),
        )
        .layer(middleware::from_fn_with_state(factory, bearer_middleware));

    Harness {
        app,
        system,
        owner,
        token_id: token.id().to_string(),
        token: token.expose(),
    }
}

async fn call(app: &Router, method: &str, uri: &str, bearer: Option<&str>) -> (StatusCode, String) {
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(token) = bearer {
        req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let res = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let body = axum::body::to_bytes(res.into_body(), 1 << 16)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

async fn stored_row(h: &Harness) -> serde_json::Value {
    let backend = h.system.backend_for_table("personal_token").unwrap();
    valence::get_record(backend.as_ref(), "personal_token", &h.token_id, valence::use_!(r"**Test:** the bearer scope suite reads the stored **personal token** to check its last-used time."))
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn token_with_the_scope_runs_as_its_person_happy() {
    let h = harness().await;
    let (status, body) = call(&h.app, "GET", "/api/magnon/tasks", Some(&h.token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("bearer-alice"), "{body}");
    // The request recorded the token's last use, as the person.
    assert!(!stored_row(&h).await["last_used_at"].is_null());
}

#[tokio::test]
async fn token_missing_the_scope_is_forbidden_sad() {
    let h = harness().await;
    let (status, _) = call(&h.app, "POST", "/api/magnon/tasks/close", Some(&h.token)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn revoked_or_unknown_token_is_unauthorized_sad() {
    let h = harness().await;
    let forged = LeptonToken::generate().expose();
    assert_eq!(
        call(&h.app, "GET", "/api/magnon/tasks", Some(&forged))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );

    let row = PersonalToken::get(&h.token_id, &h.owner, valence::use_!(r"**Test:** the bearer scope suite loads the test user's **personal token** to revoke it."))
        .await
        .unwrap()
        .unwrap();
    row.get_mutable(
        &h.owner,
        valence::use_!(
            r"**Test:** the bearer scope suite revokes the test user's **personal token**."
        ),
    )
    .set_revoked_at(Utc::now())
    .unwrap()
    .commit()
    .await
    .unwrap();
    assert_eq!(
        call(&h.app, "GET", "/api/magnon/tasks", Some(&h.token))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}
