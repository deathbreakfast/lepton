//! Axum-login session backend and token schemas for SSR hosts.
//!
//! Bridges [`lepton_identity`](../lepton_identity/index.html) users to higgs via
//! [`Backend`] and [`session_snapshot_middleware`]. All modules require the `ssr`
//! feature; there is no client-side surface.
//!
//! # Features
//!
//! - **Axum-login backend** — Provides [`Backend`], [`Credentials`], and [`User`] for
//!   email/password sessions when the host owns login cookies
//!   ([Host wiring](#host-wiring)).
//! - **Session snapshot** — Mirrors the logged-in session into higgs via
//!   [`session_snapshot_middleware`] so Leptos/SSR code can read identity from
//!   extensions ([Host wiring](#host-wiring)).
//! - **Photon WS auth** — Authenticates photon-axum WebSocket upgrades with
//!   [`PhotonAuth`] / [`extract_user_key`] when live channels need the same Backend
//!   ([Host wiring](#host-wiring)).
//! - **Token models** — Holds password-reset and verification schemas in [`generated`]
//!   for SSR token lifecycle ([Host wiring](#host-wiring)).
//! - **Profile files** — Serves profile photo upload/download through [`files`] when
//!   the product stores avatar bytes. New uploads wait in meson's quarantine store
//!   until a virus scan clears them ([Host wiring](#host-wiring)).
//! - **Product → User** — Documents hopping from a product Valence edge to identity
//!   `User` on [`lepton_identity`](../lepton_identity/index.html#product-composition).
//!
//! Token / factor Valence models live in [`generated`] (schema inventory and sealed
//! fields on each type); see workspace `SECURITY.md`. Router logical-name constants:
//! [`embedded_surreal`].
//!
//! # Getting started
//!
//! ## Host wiring
//!
//! Provides axum-login plus a higgs session snapshot on the SSR router so authenticated
//! requests carry identity into Leptos and Photon. Wire this once at host boot when the
//! product owns cookies and login.
//!
//! Prerequisites: `lepton-host-adapter` with `features = ["ssr"]`, a shared
//! higgs Valence factory, and a session store. Set `Secure` / `HttpOnly` / `SameSite` on
//! the session cookie (see workspace `SECURITY.md`).
//!
//! 1. Build [`Backend`] with the same Valence factory Arc higgs uses.
//! 2. Layer `AuthManagerLayer` + [`session_snapshot_middleware`] on the axum `Router`.
//! 3. Authenticated requests expose `Extension<higgs_identity::SessionSnapshot>`.
//! 4. Confirm with the runnable example (prints `OK — login → SessionSnapshot`).
//!
//! Errors: missing layers leave requests without a snapshot; cookie flags wrong for
//! the environment break browser sessions. Next: mount Leptos / auth UI routes on the
//! same `Router`.
//!
//! ```rust,ignore
//! use std::sync::Arc;
//!
//! use axum::{middleware, Router};
//! use axum_login::AuthManagerLayerBuilder;
//! use higgs::HiggsConfig;
//! use lepton_host_adapter::{session_snapshot_middleware, Backend};
//! use tower_sessions::{MemoryStore, SessionManagerLayer};
//!
//! // Share the same valence factory Arc with HiggsConfig.
//! let higgs: Arc<HiggsConfig> = /* host boot */;
//! let backend = Backend::new(Arc::clone(higgs.valence_factory()));
//! let session_layer = SessionManagerLayer::new(MemoryStore::default());
//! let auth_layer = AuthManagerLayerBuilder::new(backend, session_layer).build();
//!
//! let app: Router = Router::new()
//!     // .route(...) — mount Leptos routes / auth UI here
//!     .layer(middleware::from_fn(session_snapshot_middleware))
//!     .layer(auth_layer);
//! // Authenticated requests carry Extension<higgs_identity::SessionSnapshot>.
//! println!("OK — login → SessionSnapshot");
//! ```
//!
//! Runnable: `cargo run -p lepton-host-adapter --example axum_session_snapshot --features ssr`
//!
//! Success stdout: `axum_session_snapshot: OK — login → SessionSnapshot`.
//!
//! # Feature flags
//!
//! | Feature | Effect |
//! |---------|--------|
//! | `ssr` | Backend, middleware, Photon auth, files, and [`generated`] token models |
//! | `db-sqlite` (default) | Forwarded to `lepton-identity` / Valence `SQLite` |
//! | `db-hybrid` | Forwarded hybrid engine for host routers |
//!
//! # Further reading
//!
//! - [Host wiring](#host-wiring) — first-success session path
//! - [`Backend`] / [`session_snapshot_middleware`] — login + snapshot contracts
//! - [`generated`] — token and identity Valence models
//! - [`lepton_identity`](../lepton_identity/index.html) — password hash and ownership helpers
//! - [`lepton_auth`](../lepton_auth/index.html) — server functions and delivery

/// Token lifecycle Valence models and identity table types used by SSR hosts
/// (see the [crate-level walkthrough](self)).
#[cfg(feature = "ssr")]
pub mod generated;

/// Logical embedded Surreal database name/storage constants for token schemas.
#[cfg(feature = "ssr")]
pub mod embedded_surreal;

#[cfg(feature = "ssr")]
mod schemas;

/// axum-login backend + session user/credential types bridging to `lepton-identity`.
#[cfg(feature = "ssr")]
pub mod auth;

/// Middleware mirroring the axum-login session into `higgs_identity::SessionSnapshot`.
#[cfg(feature = "ssr")]
pub mod session;

/// Photon WebSocket auth extractor built on [`auth::Backend`].
#[cfg(feature = "ssr")]
pub mod photon_auth;

/// Profile photo `/api/files/*` handlers and [`files::FileByteBackend`].
#[cfg(feature = "ssr")]
pub mod files;

// Inline so crate-root rustdoc pages exist (e.g. `struct.Backend.html`). Sibling
// crates such as `lepton-auth` link those paths from their task tables.
#[cfg(feature = "ssr")]
#[doc(inline)]
pub use auth::{Backend, Credentials, User};

#[cfg(feature = "ssr")]
#[doc(inline)]
pub use axum_login::AuthSession;

#[cfg(feature = "ssr")]
#[doc(inline)]
pub use photon_auth::{extract_user_key, PhotonAuth};

#[cfg(feature = "ssr")]
#[doc(inline)]
pub use session::session_snapshot_middleware;
