//! Lepton-auth integration tests, one module per area, linked as one binary.
//!
//! Tests that install process-wide state (the service user gate, the per-owner
//! limit, the primary-clear fault hook) keep their own binaries next to this one.
//! Run one area with `cargo test -p lepton-auth --features ssr,full --test auth <module>::`.

#[path = "../support/mod.rs"]
mod support;

#[path = "../support/service_users.rs"]
mod service_users_support;

mod account_delete_privacy;
mod account_email_owner_privacy;
mod account_phone;
mod account_primary_email;
#[cfg(feature = "totp")]
mod account_wipe;
mod auth_boundaries;
mod change_password;
#[cfg(feature = "phone")]
mod confirm_account_status;
mod contact_validators;
#[cfg(all(feature = "boson-delivery", feature = "email"))]
mod delivery_attempt;
mod device_owner_privacy;
mod email_change_account_primary;
mod forbidden_deps;
mod oauth_link_settings;
#[cfg(feature = "oauth-microsoft")]
mod oauth_microsoft_signup;
#[cfg(feature = "oauth-google")]
mod oauth_pkce_state;
mod oauth_signup_collision;
mod password_hash_privacy;
mod service_users_concurrency;
#[cfg(feature = "test-utils")]
mod service_users_events;
mod service_users_lifecycle;
mod service_users_owner_delete;
mod service_users_privacy;
mod service_users_quota;
mod service_users_resolver;
mod step_up_modal_coverage_inventory;
mod step_up_session_binding;
#[cfg(feature = "totp")]
mod step_up_verify;
#[cfg(feature = "totp")]
mod totp_recovery;
#[cfg(feature = "totp")]
mod totp_seal_enroll;
#[cfg(all(feature = "test-utils", feature = "phone"))]
mod verification_tokens;
#[cfg(feature = "webauthn")]
mod webauthn_devices;
