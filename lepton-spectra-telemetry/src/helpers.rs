//! Typed recorders and loggers from Lepton Spectra schemas.
//!
//! # Examples
//!
//! ```rust,no_run
//! use lepton_spectra_telemetry::helpers::LeptonEmailSendRecorder;
//!
//! LeptonEmailSendRecorder::record(
//!     1,
//!     serde_json::json!({"driver": "smtp", "outcome": "success"}),
//! );
//! ```

/// Recorder for the `lepton_account` counter.
pub use crate::schemas::lepton_account::LeptonAccountRecorder;
/// Logger for the `lepton_auth_failure` event table.
pub use crate::schemas::lepton_auth_failure::{LeptonAuthFailure, LeptonAuthFailureLogger};
/// Recorder for the `lepton_contact` counter.
pub use crate::schemas::lepton_contact::LeptonContactRecorder;
/// Recorder for the `lepton_device` counter.
pub use crate::schemas::lepton_device::LeptonDeviceRecorder;
/// Recorder for the `lepton_email_send` counter.
pub use crate::schemas::lepton_email_send::LeptonEmailSendRecorder;
/// Recorder for the `lepton_identity_delete` counter.
pub use crate::schemas::lepton_identity_delete::LeptonIdentityDeleteRecorder;
/// Recorder for the `lepton_oauth` counter.
pub use crate::schemas::lepton_oauth::LeptonOauthRecorder;
/// Recorder for the `lepton_password_reset` counter.
pub use crate::schemas::lepton_password_reset::LeptonPasswordResetRecorder;
/// Recorder for the `lepton_service_user` counter.
pub use crate::schemas::lepton_service_user::LeptonServiceUserRecorder;
/// Recorder for the `lepton_signin` counter.
pub use crate::schemas::lepton_signin::LeptonSigninRecorder;
/// Recorder for the `lepton_signup` counter.
pub use crate::schemas::lepton_signup::LeptonSignupRecorder;
/// Recorder for the `lepton_sms_send` counter.
pub use crate::schemas::lepton_sms_send::LeptonSmsSendRecorder;
/// Recorder for the `lepton_step_up` counter.
pub use crate::schemas::lepton_step_up::LeptonStepUpRecorder;
/// Recorder for the `lepton_totp` counter.
pub use crate::schemas::lepton_totp::LeptonTotpRecorder;
/// Recorder for the `lepton_verify` counter.
pub use crate::schemas::lepton_verify::LeptonVerifyRecorder;
