//! Lepton Spectra schema modules (inventory + typed helpers + topics).
//!
//! Each module wraps one `spectra_metric!` / `spectra_schema!` under `schemas/` at the crate root.
#![allow(clippy::too_many_arguments)]

/// `lepton_email_send` counter schema.
#[path = "../schemas/lepton_email_send_spectra_metric.rs"]
pub mod lepton_email_send;

/// `lepton_sms_send` counter schema.
#[path = "../schemas/lepton_sms_send_spectra_metric.rs"]
pub mod lepton_sms_send;

/// `lepton_signup` counter schema.
#[path = "../schemas/lepton_signup_spectra_metric.rs"]
pub mod lepton_signup;

/// `lepton_signin` counter schema.
#[path = "../schemas/lepton_signin_spectra_metric.rs"]
pub mod lepton_signin;

/// `lepton_oauth` counter schema.
#[path = "../schemas/lepton_oauth_spectra_metric.rs"]
pub mod lepton_oauth;

/// `lepton_verify` counter schema.
#[path = "../schemas/lepton_verify_spectra_metric.rs"]
pub mod lepton_verify;

/// `lepton_password_reset` counter schema.
#[path = "../schemas/lepton_password_reset_spectra_metric.rs"]
pub mod lepton_password_reset;

/// `lepton_totp` counter schema.
#[path = "../schemas/lepton_totp_spectra_metric.rs"]
pub mod lepton_totp;

/// `lepton_device` counter schema.
#[path = "../schemas/lepton_device_spectra_metric.rs"]
pub mod lepton_device;

/// `lepton_service_user` counter schema.
#[path = "../schemas/lepton_service_user_spectra_metric.rs"]
pub mod lepton_service_user;

/// `lepton_contact` counter schema.
#[path = "../schemas/lepton_contact_spectra_metric.rs"]
pub mod lepton_contact;

/// `lepton_account` counter schema.
#[path = "../schemas/lepton_account_spectra_metric.rs"]
pub mod lepton_account;

/// `lepton_identity_delete` counter schema.
#[path = "../schemas/lepton_identity_delete_spectra_metric.rs"]
pub mod lepton_identity_delete;

/// `lepton_step_up` counter schema.
#[path = "../schemas/lepton_step_up_spectra_metric.rs"]
pub mod lepton_step_up;

/// `lepton_auth_failure` event schema.
#[path = "../schemas/lepton_auth_failure_spectra_schema.rs"]
pub mod lepton_auth_failure;
