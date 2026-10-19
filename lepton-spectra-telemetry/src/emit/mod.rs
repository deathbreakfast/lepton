//! Bounded-label emit helpers for Lepton Spectra counters and auth failure events.
//!
//! Prefer these over calling typed recorders with free-form label strings. Unknown
//! tokens map to `unknown` / `none` (low cardinality). Never pass PII, passwords,
//! OTPs, tokens, or raw `Display` strings as label values.

mod account;
mod common;
mod contact;
mod delivery;
mod device;
mod failure;
mod identity_delete;
mod oauth;
mod password_reset;
mod service_user;
mod signin;
mod signup;
mod step_up;
mod totp;
mod verify;

pub use account::{record_account, AccountOperation};
pub use common::{
    bound_error_class, bound_optional_channel, bound_optional_provider, AuthFactor,
    AuthFailureFlow, AuthOutcome,
};
pub use contact::{record_contact, ContactOperation};
pub use delivery::{
    bound_email_driver, bound_sms_driver, record_email_send, record_sms_send, EmailSendOutcome,
    SmsSendOutcome,
};
pub use device::{record_device, DeviceKind, DeviceOperation};
pub use failure::log_auth_failure;
pub use identity_delete::{record_identity_delete, IdentityDeleteOperation};
pub use oauth::{
    bound_oauth_provider, record_oauth, OAuthIntentLabel, OAuthProviderLabel, OAuthStage,
};
pub use password_reset::{record_password_reset, PasswordResetStage};
pub use service_user::{record_service_user, ServiceUserOperation};
pub use signin::{record_signin, SigninStage};
pub use signup::record_signup;
pub use step_up::{record_step_up, StepUpPath};
pub use totp::{record_totp, TotpOperation};
pub use verify::{bound_verify_channel, record_verify, VerifyChannel, VerifyStage};
