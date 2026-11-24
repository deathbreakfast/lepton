//! Bearer-token middleware for Lepton tokens, and the per-route scope check.
//!
//! [`bearer_middleware`] reads `Authorization: Bearer lptk_...` and checks it with
//! [the token check](lepton_identity::tokens::verify_bearer_token). For a token that verifies
//! it inserts two request extensions:
//!
//! - [`BearerCaller`]: who the token acts as (a person or a service user) and its scopes.
//! - [`BearerValence`]: a request-scoped Valence opened as that person or service user.
//!   Handlers run the request on it, so privacy rules see the token's own actor.
//!
//! It never inserts a [`SessionSnapshot`](higgs_identity::SessionSnapshot): that type means a
//! person signed in through a browser, and a bearer request is not one.
//!
//! [`require_scope`] goes on each route (or router) an API exposes, naming the scope that API
//! needs. A bearer request whose token lacks it gets `403`. The person's or service user's own
//! permissions still decide what the handler lets the call do.
//!
//! A request with no `Authorization` header, or one with another scheme, passes through both
//! untouched, so session-cookie routes keep working. A `Bearer` header that does not verify
//! gets `401` with no detail about why.
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use axum::{middleware, routing::get, Router};
//! use higgs_core::HiggsValenceFactory;
//! use lepton_host_adapter::{bearer_middleware, require_scope};
//! use lepton_identity::tokens::ApiScope;
//!
//! fn api(factory: Arc<dyn HiggsValenceFactory>) -> Router {
//!     let read = ApiScope::parse("magnon:read").expect("valid scope");
//!     let write = ApiScope::parse("magnon:write").expect("valid scope");
//!     Router::new()
//!         .route("/api/magnon/tasks", get(|| async { "tasks" }))
//!         .route_layer(middleware::from_fn_with_state(read, require_scope))
//!         .merge(
//!             Router::new()
//!                 .route("/api/magnon/tasks/close", axum::routing::post(|| async { "closed" }))
//!                 .route_layer(middleware::from_fn_with_state(write, require_scope)),
//!         )
//!         .layer(middleware::from_fn_with_state(factory, bearer_middleware))
//! }
//! ```

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};
use higgs_core::HiggsValenceFactory;
use lepton_identity::tokens::{
    record_token_use, verify_bearer_token, ApiScope, LeptonToken, TokenPrincipal, VerifiedToken,
};
use valence::{Actor, Valence};

/// How stale `last_used_at` may get before a request writes it again.
const TOUCH_EVERY: Duration = Duration::minutes(5);

/// The verified token behind a bearer request, in request extensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BearerCaller {
    /// Who the token acts as.
    pub principal: TokenPrincipal,
    /// The row id of the token that was presented.
    pub token_id: String,
    /// The APIs the token may call.
    pub scopes: Vec<ApiScope>,
}

impl BearerCaller {
    /// The Valence actor this request runs as.
    #[must_use]
    pub fn actor(&self) -> Actor {
        self.principal.actor()
    }

    /// Whether the token may call the API `scope` names.
    #[must_use]
    pub fn has_scope(&self, scope: &ApiScope) -> bool {
        self.scopes.contains(scope)
    }
}

impl From<VerifiedToken> for BearerCaller {
    fn from(v: VerifiedToken) -> Self {
        Self {
            principal: v.principal,
            token_id: v.token_id,
            scopes: v.scopes,
        }
    }
}

/// A Valence opened as the bearer token's person or service user, in request extensions.
#[derive(Clone)]
pub struct BearerValence(pub Valence);

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
    )
        .into_response()
}

/// The bearer credential, or `None` when the header is absent or uses another scheme.
fn bearer_credential(req: &Request) -> Option<&str> {
    let value = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, rest) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then_some(rest.trim())
}

fn build(factory: &dyn HiggsValenceFactory, actor: &Actor) -> Option<Valence> {
    let actor_json = serde_json::to_value(actor).ok()?;
    factory.build(&actor_json).ok()
}

/// Axum middleware: verify a Lepton bearer token and insert [`BearerCaller`] and
/// [`BearerValence`].
///
/// Mount with `middleware::from_fn_with_state(higgs.valence_factory().clone(), bearer_middleware)`.
/// The token lookup runs before any identity exists, so it uses the factory's System-level
/// handle, the same narrow exception [`Backend`](crate::Backend) makes for sign-in. That
/// handle also reads the row when recording the token's last use; the write itself, and
/// everything downstream, runs as the token's own actor.
pub async fn bearer_middleware(
    State(factory): State<Arc<dyn HiggsValenceFactory>>,
    mut req: Request,
    next: Next,
) -> Response {
    let Some(raw) = bearer_credential(&req) else {
        return next.run(req).await;
    };
    // Refuse a token that is not even shaped like one before touching storage.
    if LeptonToken::parse(raw).is_err() {
        return unauthorized();
    }
    let lookup_actor = Actor::System {
        operation: "lepton_bearer".to_string(),
    };
    let Some(lookup) = build(factory.as_ref(), &lookup_actor) else {
        tracing::warn!(target: "lepton.token", "bearer: valence factory build failed");
        return unauthorized();
    };
    let Some(verified) = verify_bearer_token(raw, &lookup).await else {
        return unauthorized();
    };
    let Some(caller) = build(factory.as_ref(), &verified.principal.actor()) else {
        tracing::warn!(target: "lepton.token", "bearer: valence factory build failed");
        return unauthorized();
    };
    if verified
        .last_used_at
        .is_none_or(|at| Utc::now() - at >= TOUCH_EVERY)
    {
        if let Err(e) = record_token_use(&verified, &lookup, &caller).await {
            tracing::warn!(target: "lepton.token", error = %e, "bearer: last use not recorded");
        }
    }
    req.extensions_mut().insert(BearerCaller::from(verified));
    req.extensions_mut().insert(BearerValence(caller));
    next.run(req).await
}

/// Axum middleware: refuse a bearer request whose token lacks `scope`.
///
/// Mount per route or router with
/// `route_layer(middleware::from_fn_with_state(scope, require_scope))`, inside
/// [`bearer_middleware`]. A request with no [`BearerCaller`] (a session-cookie request, or no
/// credentials at all) passes through; the route's own session checks apply to it.
pub async fn require_scope(State(scope): State<ApiScope>, req: Request, next: Next) -> Response {
    if let Some(caller) = req.extensions().get::<BearerCaller>() {
        if !caller.has_scope(&scope) {
            tracing::debug!(
                target: "lepton.token",
                scope = scope.as_str(),
                "bearer: token lacks the route's scope"
            );
            return StatusCode::FORBIDDEN.into_response();
        }
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request as HttpRequest, middleware, routing::get, Router};
    use tower::ServiceExt;

    use super::*;

    struct NoFactory;

    impl HiggsValenceFactory for NoFactory {
        fn build(&self, _actor_json: &serde_json::Value) -> anyhow::Result<Valence> {
            anyhow::bail!("no storage in this test")
        }
    }

    fn app() -> Router {
        let factory: Arc<dyn HiggsValenceFactory> = Arc::new(NoFactory);
        Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(middleware::from_fn_with_state(factory, bearer_middleware))
    }

    async fn status(auth: Option<&str>) -> StatusCode {
        let mut req = HttpRequest::builder().uri("/");
        if let Some(value) = auth {
            req = req.header(header::AUTHORIZATION, value);
        }
        app()
            .oneshot(req.body(Body::empty()).expect("request"))
            .await
            .expect("response")
            .status()
    }

    #[tokio::test]
    async fn no_header_or_other_scheme_passes_through_happy() {
        assert_eq!(status(None).await, StatusCode::OK);
        assert_eq!(status(Some("Basic dXNlcjpwYXNz")).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn bad_bearer_is_unauthorized_sad() {
        let well_shaped = LeptonToken::generate().expose();
        let retired = well_shaped.replacen("lptk_", "lpt_", 1);
        for value in [
            "Bearer".to_string(),
            "Bearer ".to_string(),
            "Bearer nope".to_string(),
            "bearer lptk_x_y".to_string(),
            format!("Bearer {retired}"),
            format!("Bearer {}", well_shaped.replacen("lptk_", "fbtk_", 1)),
            // Well shaped, but the factory cannot reach storage: still a flat 401.
            format!("Bearer {well_shaped}"),
        ] {
            let got = status(Some(&value)).await;
            // A lone "Bearer" has no credential part and is treated as another scheme.
            if value == "Bearer" {
                assert_eq!(got, StatusCode::OK, "{value}");
            } else {
                assert_eq!(got, StatusCode::UNAUTHORIZED, "{value}");
            }
        }
    }

    fn scope(raw: &str) -> ApiScope {
        ApiScope::parse(raw).expect("scope")
    }

    /// A router that requires `magnon:read`, with an optional caller already in extensions.
    async fn scoped_status(caller: Option<BearerCaller>) -> StatusCode {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .route_layer(middleware::from_fn_with_state(
                scope("magnon:read"),
                require_scope,
            ));
        let mut req = HttpRequest::builder()
            .uri("/")
            .body(Body::empty())
            .expect("request");
        if let Some(caller) = caller {
            req.extensions_mut().insert(caller);
        }
        app.oneshot(req).await.expect("response").status()
    }

    fn caller(scopes: &[&str]) -> BearerCaller {
        BearerCaller {
            principal: TokenPrincipal::Person(Actor::User {
                user_id: "alice".into(),
            }),
            token_id: "t".into(),
            scopes: scopes.iter().map(|s| scope(s)).collect(),
        }
    }

    #[tokio::test]
    async fn require_scope_allows_a_token_with_the_scope_happy() {
        assert_eq!(
            scoped_status(Some(caller(&["spectra:read", "magnon:read"]))).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn require_scope_refuses_a_token_without_it_sad() {
        assert_eq!(
            scoped_status(Some(caller(&["magnon:write"]))).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            scoped_status(Some(caller(&[]))).await,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn require_scope_passes_session_requests_through() {
        assert_eq!(scoped_status(None).await, StatusCode::OK);
    }
}
