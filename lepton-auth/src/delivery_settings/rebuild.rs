//! Build email and SMS services from saved delivery settings.
//!
//! The host resolves secrets from its vault and passes them in as plain
//! strings; nothing here reads the environment or stores a secret.

#[cfg(feature = "email")]
use std::sync::Arc;

#[cfg(feature = "phone")]
use lepton_sms::{SmsDeliveryService, SmsServiceBuilder};
#[cfg(feature = "email")]
use lepton_smtp::{EmailDeliveryService, EmailServiceBuilder, SmtpConfig};

#[cfg(any(feature = "email", feature = "phone"))]
use super::settings::DeliveryError;
#[cfg(feature = "email")]
use super::settings::{EmailCandidate, EmailDriverChoice};
#[cfg(feature = "phone")]
use super::settings::{SmsCandidate, SmsMode};

#[cfg(any(feature = "email", feature = "phone"))]
const fn invalid(field: &'static str, reason: &'static str) -> DeliveryError {
    DeliveryError::Invalid { field, reason }
}

/// Email service for `candidate`. `smtp_password` and `sendgrid_api_key` are the
/// resolved secret values for the chosen driver.
///
/// # Errors
///
/// [`DeliveryError::Invalid`] when the candidate fails validation, a required
/// secret is missing, or the driver is not compiled in (`twilio` feature).
#[cfg(feature = "email")]
pub fn build_email_service(
    candidate: &EmailCandidate,
    smtp_password: Option<&str>,
    sendgrid_api_key: Option<&str>,
) -> Result<Arc<dyn EmailDeliveryService>, DeliveryError> {
    candidate.validate()?;
    let builder = match candidate.driver {
        EmailDriverChoice::Off => EmailServiceBuilder::new().noop(),
        EmailDriverChoice::Smtp => {
            let mut cfg = SmtpConfig::builder()
                .host(candidate.smtp_host.trim())
                .port(candidate.smtp_port)
                .use_tls(candidate.smtp_tls)
                .from_email(candidate.from_email.trim());
            if !candidate.from_name.trim().is_empty() {
                cfg = cfg.from_name(candidate.from_name.trim());
            }
            if !candidate.smtp_username.is_empty() {
                let password = smtp_password
                    .filter(|p| !p.is_empty())
                    .ok_or_else(|| invalid("smtp_password", "is required"))?;
                cfg = cfg.username(&candidate.smtp_username).password(password);
            }
            EmailServiceBuilder::new().smtp(
                cfg.build()
                    .map_err(|_| invalid("smtp", "settings are not usable"))?,
            )
        }
        EmailDriverChoice::SendGrid => sendgrid_builder(candidate, sendgrid_api_key)?,
        EmailDriverChoice::DirectMx => {
            let mut cfg =
                lepton_smtp::DirectMxConfig::builder().from_email(candidate.from_email.trim());
            if !candidate.from_name.trim().is_empty() {
                cfg = cfg.from_name(candidate.from_name.trim());
            }
            EmailServiceBuilder::new().direct_mx(
                cfg.build()
                    .map_err(|_| invalid("direct_mx", "settings are not usable"))?,
            )
        }
    };
    builder
        .build()
        .map_err(|_| invalid("email", "settings are not usable"))
}

#[cfg(all(feature = "email", feature = "twilio"))]
fn sendgrid_builder(
    candidate: &EmailCandidate,
    api_key: Option<&str>,
) -> Result<EmailServiceBuilder, DeliveryError> {
    let key = api_key
        .filter(|k| !k.is_empty())
        .ok_or_else(|| invalid("sendgrid_api_key", "is required"))?;
    let mut cfg = lepton_smtp::TwilioEmailConfig::builder()
        .api_key(key)
        .from_email(candidate.from_email.trim());
    if !candidate.from_name.trim().is_empty() {
        cfg = cfg.from_name(candidate.from_name.trim());
    }
    Ok(EmailServiceBuilder::new().twilio(
        cfg.build()
            .map_err(|_| invalid("sendgrid", "settings are not usable"))?,
    ))
}

#[cfg(all(feature = "email", not(feature = "twilio")))]
fn sendgrid_builder(
    _candidate: &EmailCandidate,
    _api_key: Option<&str>,
) -> Result<EmailServiceBuilder, DeliveryError> {
    Err(invalid("driver", "SendGrid is not compiled in"))
}

/// SMS service for `candidate`. `twilio_api_secret` is the resolved API secret.
///
/// # Errors
///
/// [`DeliveryError::Invalid`] when the candidate fails validation, the secret
/// is missing, or Twilio is not compiled in (`twilio` feature).
#[cfg(feature = "phone")]
pub fn build_sms_service(
    candidate: &SmsCandidate,
    twilio_api_secret: Option<&str>,
) -> Result<std::sync::Arc<dyn SmsDeliveryService>, DeliveryError> {
    candidate.validate()?;
    let builder = match candidate.mode {
        SmsMode::Off => SmsServiceBuilder::new().noop(),
        SmsMode::Verify | SmsMode::Messages => twilio_builder(candidate, twilio_api_secret)?,
    };
    builder
        .build()
        .map_err(|_| invalid("sms", "settings are not usable"))
}

#[cfg(all(feature = "phone", feature = "twilio"))]
fn twilio_builder(
    candidate: &SmsCandidate,
    api_secret: Option<&str>,
) -> Result<SmsServiceBuilder, DeliveryError> {
    let secret = api_secret
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid("twilio_api_secret", "is required"))?;
    let bad = |_| invalid("twilio", "settings are not usable");
    if candidate.mode == SmsMode::Verify {
        let cfg = lepton_sms::TwilioVerifyConfig::builder()
            .account_sid(candidate.twilio_account_sid.trim())
            .api_key(candidate.twilio_api_key_sid.trim())
            .api_secret(secret)
            .service_sid(candidate.twilio_verify_service_sid.trim())
            .build()
            .map_err(bad)?;
        Ok(SmsServiceBuilder::new().twilio_verify(cfg))
    } else {
        let cfg = lepton_sms::TwilioSmsConfig::builder()
            .account_sid(candidate.twilio_account_sid.trim())
            .api_key(candidate.twilio_api_key_sid.trim())
            .api_secret(secret)
            .from(candidate.twilio_from.trim())
            .build()
            .map_err(bad)?;
        Ok(SmsServiceBuilder::new().twilio(cfg))
    }
}

#[cfg(all(feature = "phone", not(feature = "twilio")))]
fn twilio_builder(
    _candidate: &SmsCandidate,
    _api_secret: Option<&str>,
) -> Result<SmsServiceBuilder, DeliveryError> {
    Err(invalid("mode", "Twilio is not compiled in"))
}
