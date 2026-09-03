//! Leptos `#[server]` functions backing the auth UI.
//!
//! Signup, signin, logout, password reset, account settings, devices, TOTP enroll,
//! and OAuth link / unlink. Form components in
//! [`lepton_auth_ui`](../lepton_auth_ui/index.html) call these on submit.
//!
//! These functions register with the host through Leptos `generate_route_list` /
//! `leptos_routes_with_context`. You do not mount them as separate axum handlers.
//!
//! Hosts that need custom ceremony compose library APIs ([`crate::factor`],
//! [`crate::signup_api`], [`crate::totp`], [`crate::oauth`]) instead of calling these
//! server fns from outside the UI. For a host-owned sensitive mutation with step-up,
//! see [`crate::factor`] and `examples/step_up_totp`.

/// Account settings server functions (overview, password, email changes).
pub mod account;
/// Account confirm funnel (status, phone OTP, confirm).
pub mod confirm_account;
/// Trusted devices / passkey server functions.
pub mod devices;
/// Logout server function.
pub mod logout;
/// OAuth begin / callback server functions.
pub mod oauth;
/// OAuth link / unlink server functions (Account Settings).
pub mod oauth_settings;
/// Password reset request/completion server functions.
pub mod password_reset;
/// Sign-in server function.
pub mod signin;
/// Signup server function.
pub mod signup;
/// Step-up TOTP verify (opens a session sudo window).
pub mod step_up;
/// TOTP enroll / disable / recovery server functions (Account Settings).
pub mod totp;
