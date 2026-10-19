//! Transport `*Payload` / `*_TOPIC` DTOs from Lepton Spectra schemas.
//!
//! # Examples
//!
//! ```rust,no_run
//! use lepton_spectra_telemetry::topics::{LeptonEmailSendPayload, LEPTON_EMAIL_SEND_TOPIC};
//!
//! assert_eq!(LeptonEmailSendPayload::topic(), LEPTON_EMAIL_SEND_TOPIC);
//! ```

/// Payload and topic constant for `lepton_account`.
pub use crate::schemas::lepton_account::{LeptonAccountPayload, LEPTON_ACCOUNT_TOPIC};
/// Payload and topic constant for `lepton_auth_failure`.
pub use crate::schemas::lepton_auth_failure::{
    LeptonAuthFailurePayload, LEPTON_AUTH_FAILURE_TOPIC,
};
/// Payload and topic constant for `lepton_contact`.
pub use crate::schemas::lepton_contact::{LeptonContactPayload, LEPTON_CONTACT_TOPIC};
/// Payload and topic constant for `lepton_device`.
pub use crate::schemas::lepton_device::{LeptonDevicePayload, LEPTON_DEVICE_TOPIC};
/// Payload and topic constant for `lepton_email_send`.
pub use crate::schemas::lepton_email_send::{LeptonEmailSendPayload, LEPTON_EMAIL_SEND_TOPIC};
/// Payload and topic constant for `lepton_identity_delete`.
pub use crate::schemas::lepton_identity_delete::{
    LeptonIdentityDeletePayload, LEPTON_IDENTITY_DELETE_TOPIC,
};
/// Payload and topic constant for `lepton_oauth`.
pub use crate::schemas::lepton_oauth::{LeptonOauthPayload, LEPTON_OAUTH_TOPIC};
/// Payload and topic constant for `lepton_password_reset`.
pub use crate::schemas::lepton_password_reset::{
    LeptonPasswordResetPayload, LEPTON_PASSWORD_RESET_TOPIC,
};
/// Payload and topic constant for `lepton_service_user`.
pub use crate::schemas::lepton_service_user::{
    LeptonServiceUserPayload, LEPTON_SERVICE_USER_TOPIC,
};
/// Payload and topic constant for `lepton_signin`.
pub use crate::schemas::lepton_signin::{LeptonSigninPayload, LEPTON_SIGNIN_TOPIC};
/// Payload and topic constant for `lepton_signup`.
pub use crate::schemas::lepton_signup::{LeptonSignupPayload, LEPTON_SIGNUP_TOPIC};
/// Payload and topic constant for `lepton_sms_send`.
pub use crate::schemas::lepton_sms_send::{LeptonSmsSendPayload, LEPTON_SMS_SEND_TOPIC};
/// Payload and topic constant for `lepton_step_up`.
pub use crate::schemas::lepton_step_up::{LeptonStepUpPayload, LEPTON_STEP_UP_TOPIC};
/// Payload and topic constant for `lepton_totp`.
pub use crate::schemas::lepton_totp::{LeptonTotpPayload, LEPTON_TOTP_TOPIC};
/// Payload and topic constant for `lepton_verify`.
pub use crate::schemas::lepton_verify::{LeptonVerifyPayload, LEPTON_VERIFY_TOPIC};
