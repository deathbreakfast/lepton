//! Leptos auth dialogs and embeddable forms composed with Orbital.
//!
//! Mount [`AuthDialog`] (or embed [`SigninContent`] / [`SignupContent`]) in the host
//! shell. Server functions and library APIs live in [`lepton_auth`]; this crate is the
//! Orbital UI surface. Auth UI `#[server]` functions in [`lepton_auth::actions`] register
//! through Leptos `generate_route_list` / `leptos_routes_with_context` — you do not mount
//! them as separate axum handlers. Session chrome (`get_session` / `init_auth_resource`)
//! wires in from the host app shell.
//!
//! # Features
//!
//! - **Auth dialog shell** — Provides [`AuthDialog`] for sign-in, sign-up, and log-out
//!   in the host shell. Start here when the product needs a modal auth entry
//!   ([Mount `AuthDialog`](#mount-authdialog-shell)). Dedicated `/auth/*` pages use
//!   [`lepton_auth::paths`] ([Routes `/auth/*`](#routes-auth)).
//! - **Embeddable forms** — Offers [`SigninContent`], [`SignupContent`], and
//!   [`LogoutContent`] when you want the forms without the modal chrome
//!   ([Mount `AuthDialog`](#mount-authdialog-shell)).
//! - **Password reset** — Covers request and confirm UI via [`PasswordResetDialog`]
//!   and content components for forgotten-password flows
//!   ([Mount `AuthDialog`](#mount-authdialog-shell)).
//! - **OAuth UI** — Renders [`OAuthProviderButtons`] and [`OAuthCallbackContent`] when
//!   `oauth-*` features are on and the host exposes provider login
//!   ([OAuth buttons](#oauth-buttons)).
//! - **Step-up** — Enables re-proof before sensitive ops with
//!   [`provide_step_up_controller`] and [`StepUpDialog`] when an already-signed-in user
//!   must confirm identity again ([Step-up](#step-up-critical-action)).
//! - **Confirm account** — Surfaces [`ConfirmAccountPrompt`] / [`ConfirmAccountPage`]
//!   after signup when email or phone confirmation is still outstanding
//!   ([Mount `AuthDialog`](#mount-authdialog-shell)).
//!
//! # Getting started
//!
//! ## Mount `AuthDialog` (shell)
//!
//! Mount `AuthDialog` when the host shell needs a modal entry for sign-in, sign-up, and
//! log-out. Provide the step-up controller once so later sensitive actions can reopen MFA
//! without remounting.
//!
//! Prerequisites: host Leptos app with `lepton-auth-ui` (`ssr` and/or `hydrate`), and
//! `lepton-auth` actions registered on the route list.
//!
//! 1. Create `open` / `kind` / `referer` signals.
//! 2. Call [`provide_step_up_controller`] once (keeps step-up available for later).
//! 3. Mount [`AuthDialog`] + [`StepUpDialog`].
//! 4. Toggle `open.set(true)` — observable: dialog visibility follows `open.get()`.
//!
//! Errors: missing controller context fails step-up later; unregistered actions fail
//! form submits at runtime. Next: [Step-up](#step-up-critical-action) or
//! [Routes `/auth/*`](#routes-auth).
//!
//! ```rust,ignore
//! use lepton_auth_ui::{
//!     AuthDialog, AuthDialogCallbacks, AuthDialogKind, provide_step_up_controller, StepUpDialog,
//! };
//! use leptos::prelude::*;
//!
//! let open = RwSignal::new(false);
//! let kind = RwSignal::new(AuthDialogKind::Signin);
//! let referer = Signal::derive(|| "/welcome".to_string());
//! let step_up = provide_step_up_controller();
//! assert!(!step_up.open().get());
//!
//! view! {
//!     <button type="button" on:click=move |_| open.set(true)>"Sign in"</button>
//!     <AuthDialog
//!         open=open.into()
//!         kind=kind.into()
//!         referer=referer
//!         callbacks=AuthDialogCallbacks {
//!             on_close: Some(Callback::new(move |()| open.set(false))),
//!             on_success: Some(Callback::new(move |()| open.set(false))),
//!             on_switch_signin: Some(Callback::new(move |()| kind.set(AuthDialogKind::Signin))),
//!             on_switch_signup: Some(Callback::new(move |()| kind.set(AuthDialogKind::Signup))),
//!             ..Default::default()
//!         }
//!     />
//!     <StepUpDialog/>
//! }
//! open.set(true);
//! assert!(open.get());
//! ```
//!
//! Embed forms without the modal: [`SigninContent`], [`SignupContent`], [`LogoutContent`].
//! Custom chrome / brand marks ([`AuthModalShell`], [`GoogleMark`], [`GitHubMark`],
//! [`StepUpContent`], [`OAuthProviderButtons`]) are for hosts that compose their own shell.
//!
//! ## OAuth buttons
//!
//! Enable OAuth UI on the host (SSR + hydrate), then set boot env for the
//! provider exchange:
//!
//! ```rust,ignore
//! // app/Cargo.toml hydrate + ssr:
//! //   "lepton-auth-app/oauth-google",
//! //   "lepton-auth-app/oauth-github",
//! // Boot: UF_PUBLIC_BASE_URL + UF_OAUTH_* or UF_OAUTH_USE_MOCK=1
//! use lepton_auth_ui::OAuthProviderButtons;
//! use leptos::prelude::*;
//!
//! view! { <OAuthProviderButtons referer=Signal::derive(|| "/welcome".into()) /> }
//! // Neither oauth-* feature: empty. Both features: divider + both buttons.
//! ```
//!
//! ## Routes (`/auth/*`)
//!
//! The host owns routes. Use [`lepton_auth::paths`] constants and mount pages that
//! open [`AuthDialog`] (or embed content components). Typical paths:
//! [`SIGNIN`](lepton_auth::paths::SIGNIN), [`SIGNUP`](lepton_auth::paths::SIGNUP),
//! [`LOGOUT`](lepton_auth::paths::LOGOUT),
//! [`RESET_PASSWORD_REQUEST`](lepton_auth::paths::RESET_PASSWORD_REQUEST),
//! [`RESET_PASSWORD_CONFIRM`](lepton_auth::paths::RESET_PASSWORD_CONFIRM),
//! [`OAUTH_CALLBACK`](lepton_auth::paths::OAUTH_CALLBACK).
//!
//! ```rust,ignore
//! use leptos_router::components::{Route, Routes};
//! use leptos_router::path;
//!
//! // Inside your <Router>:
//! view! {
//!     <Routes fallback=|| view! { <p>"Not found"</p> }>
//!         <Route path=path!("/auth/signin") view=SigninPage/>
//!         <Route path=path!("/auth/signup") view=SignupPage/>
//!         <Route path=path!("/auth/oauth/callback") view=OAuthCallbackPage/>
//!     </Routes>
//! }
//! ```
//!
//! ## Step-up (critical action)
//!
//! Step-up re-proofs an already signed-in user before a sensitive mutation. Mount
//! [`StepUpDialog`] once after [`provide_step_up_controller`], then call
//! [`StepUpController::request`] when a server fn returns `STEP_UP:step_up_required`
//! (or before a known Tier A action). Verify factors with
//! [`lepton_auth::factor::FactorChallengeService`] (or password re-check) and finish
//! with [`StepUpController::complete_success`] / [`StepUpController::report_error`].
//!
//! Observable: after `request`, [`StepUpController::open`] is `true` until success,
//! error report, or cancel.
//!
//! **Prerequisites:** Host already called [`provide_step_up_controller`] (often
//! beside [`AuthDialog`]); `lepton-auth` step-up server fn registered.
//!
//! ```rust,ignore
//! use lepton_auth_ui::{
//!     provide_step_up_controller, StepUpDialog, StepUpPolicy, StepUpRequest,
//! };
//! use leptos::prelude::*;
//!
//! let step_up = provide_step_up_controller();
//! view! { <StepUpDialog/> };
//!
//! step_up.request(
//!     StepUpRequest {
//!         title: "Confirm it's you".into(),
//!         description: Some("Enter your authenticator code.".into()),
//!         policy: StepUpPolicy::Totp,
//!     },
//!     Callback::new(move |factors| {
//!         let step_up = step_up;
//!         leptos::task::spawn_local(async move {
//!             match grant_permission(target, factors.totp_code).await {
//!                 Ok(()) => step_up.complete_success(),
//!                 Err(e) => step_up.report_error(e.to_string()),
//!             }
//!         });
//!     }),
//! );
//! assert!(step_up.open().get());
//! ```
//!
//! For password + TOTP, use [`StepUpPolicy::PasswordAndTotp`] and pass both factors
//! into your server fn. Server-side verify: [`lepton_auth::factor`].
//!
//! # Feature flags
//!
//! | Feature | Role |
//! |---------|------|
//! | `ssr` | Server-side rendering of auth UI |
//! | `hydrate` | Client hydration |
//! | `oauth-google` | Continue with Google (and the “or” divider) in [`OAuthProviderButtons`] |
//! | `oauth-github` | Continue with GitHub (and the “or” divider) in [`OAuthProviderButtons`] |
//!
//! Account creation UI ([`SignupContent`]) is always included. OAuth buttons
//! render only when the matching `oauth-*` features are enabled on this crate
//! (forward [`lepton_auth`] `oauth-google` / `oauth-github`). Hosts must enable
//! the same features on both SSR and hydrate graphs.
//!
//! # Further reading
//!
//! - [Mount `AuthDialog`](#mount-authdialog-shell) / [Step-up](#step-up-critical-action)
//! - [`lepton_auth`](../lepton_auth/index.html) — server functions and delivery
//! - Workspace `lepton-auth-ui-e2e` — Playwright browser coverage

#![recursion_limit = "256"]

/// Leptos UI components for the auth flows (dialogs and embeddable form content).
pub mod components;

pub use components::{
    confirm_account_status_resource, provide_step_up_controller, use_step_up_controller,
    AuthDialog, AuthDialogCallbacks, AuthDialogKind, AuthModalShell, ConfirmAccountPage,
    ConfirmAccountPrompt, ConfirmAccountPromptVariant, GitHubMark, GoogleMark, LogoutContent,
    OAuthCallbackContent, OAuthProviderButtons, PasswordResetConfirmContent, PasswordResetDialog,
    PasswordResetDialogKind, PasswordResetRequestContent, SigninContent, SignupContent,
    StepUpContent, StepUpController, StepUpDialog, StepUpFactors, StepUpPolicy, StepUpRequest,
};
