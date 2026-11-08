//! Bearer-token middleware for service users.
//!
//! [`bearer_middleware`] reads `Authorization: Bearer lpt_...`, checks it with
//! [the token check](lepton_identity::service_users::verify_bearer_token), and inserts a
//! [`ServiceUserCaller`] request extension. It never inserts a
//! [`SessionSnapshot`](higgs_identity::SessionSnapshot): that type means a signed-in person, and a
//! service user is not one. Handlers (and Higgs, once it can build a request context from a
//! verified bearer) read `Extension<ServiceUserCaller>` and open Valence as
//! [`ServiceUserCaller::actor`].
//!
//! A request with no `Authorization` header, or one with another scheme, passes through
//! untouched so session-cookie routes keep working. A `Bearer` header that does not verify gets
//! `401` with no detail about why.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use higgs_core::HiggsValenceFactory;
use lepton_identity::service_users::{
    verify_bearer_token, ServiceUserId, ServiceUserToken, VerifiedServiceUser,
};
use valence::Actor;

/// The verified service user behind a bearer request, in request extensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceUserCaller {
    /// The service user the token acts as.
    pub service_user: ServiceUserId,
    /// The user who owns that service user.
    pub owner: Actor,
    /// The row id of the token that was presented.
    pub token_id: String,
}

impl ServiceUserCaller {
    /// The Valence actor to run this request as.
    #[must_use]
    pub fn actor(&self) -> Actor {
        self.service_user.actor()
    }
}

impl From<VerifiedServiceUser> for ServiceUserCaller {
    fn from(v: VerifiedServiceUser) -> Self {
        Self {
            service_user: v.service_user,
            owner: v.owner,
            token_id: v.token_id,
        }
    }
}

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

/// Axum middleware: verify a service user's bearer token and insert [`ServiceUserCaller`].
///
/// Mount with `middleware::from_fn_with_state(higgs.valence_factory().clone(), bearer_middleware)`.
/// The token lookup runs before any identity exists, so it uses the factory's System-level
/// handle, the same narrow exception [`Backend`](crate::Backend) makes for sign-in. Nothing
/// downstream inherits that handle.
pub async fn bearer_middleware(
    State(factory): State<Arc<dyn HiggsValenceFactory>>,
    mut req: Request,
    next: Next,
) -> Response {
    let Some(raw) = bearer_credential(&req) else {
        return next.run(req).await;
    };
    // Refuse a token that is not even shaped like one before touching storage.
    if ServiceUserToken::parse(raw).is_err() {
        return unauthorized();
    }
    let actor = Actor::System {
        operation: "service_user_bearer".to_string(),
    };
    let Ok(actor_json) = serde_json::to_value(&actor) else {
        return unauthorized();
    };
    let Ok(valence) = factory.build(&actor_json) else {
        tracing::warn!(target: "lepton.service_user", "bearer: valence factory build failed");
        return unauthorized();
    };
    match verify_bearer_token(raw, &valence).await {
        Some(verified) => {
            req.extensions_mut()
                .insert(ServiceUserCaller::from(verified));
            next.run(req).await
        }
        None => unauthorized(),
    }
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request as HttpRequest, middleware, routing::get, Router};
    use tower::ServiceExt;
    use valence::Valence;

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
        let well_shaped = ServiceUserToken::generate().expose();
        for value in [
            "Bearer".to_string(),
            "Bearer ".to_string(),
            "Bearer nope".to_string(),
            "bearer lpt_x_y".to_string(),
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
}
