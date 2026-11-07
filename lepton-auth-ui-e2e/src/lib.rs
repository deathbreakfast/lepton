//! Playwright e2e host for `lepton-auth-ui` (Mailpit + SMS sink).
//!
//! This crate is a harness binary/app surface, not a publishable library. Operator
//! setup, ports, and scenario notes live in the crate `README.md`. Product auth UI
//! docs: [`lepton_auth_ui`](../lepton_auth_ui/index.html).

#![allow(missing_docs)]
#![recursion_limit = "256"]

pub mod app;
pub mod connected_accounts_section;
pub mod devices_section;
pub mod page_shell;
pub mod step_up_demo;
pub mod totp_section;
pub mod wipe_section;

#[cfg(feature = "ssr")]
pub mod boot;
#[cfg(feature = "ssr")]
pub mod seed;
#[cfg(feature = "ssr")]
pub mod service_user_gate;

pub use app::{shell, App};

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    use app::App;
    console_error_panic_hook::set_once();
    tracing_wasm::set_as_global_default();
    leptos::mount::hydrate_body(App);
}
