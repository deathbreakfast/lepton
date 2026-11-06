//! Email transport driver selection.

use crate::error::EmailDeliveryError;

/// Env var selecting the active [`EmailDriver`] (see [`EmailDriver::from_env`]).
pub const EMAIL_DRIVER_ENV: &str = "UF_EMAIL_DRIVER";
/// [`EMAIL_DRIVER_ENV`] value selecting [`EmailDriver::Smtp`].
pub const EMAIL_DRIVER_SMTP: &str = "smtp";
/// [`EMAIL_DRIVER_ENV`] value selecting [`EmailDriver::DirectMx`].
pub const EMAIL_DRIVER_DIRECT_MX: &str = "direct_mx";
/// Accepts mail immediately without sending (CI / local E2E; set `UF_EMAIL_DRIVER=noop`).
pub const EMAIL_DRIVER_NOOP: &str = "noop";
/// [`EMAIL_DRIVER_ENV`] value selecting Twilio `SendGrid` (`feature = "twilio"`).
#[cfg(feature = "twilio")]
pub const EMAIL_DRIVER_TWILIO: &str = "twilio";

/// Which transport [`crate::EmailServiceBuilder`] / [`crate::build_email_service_from_env`] should construct.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmailDriver {
    /// Deliver via a configured SMTP relay (see [`crate::SmtpConfig`]).
    Smtp,
    /// Deliver directly to the recipient domain's MX hosts (see [`crate::DirectMxConfig`]).
    DirectMx,
    /// Accept mail without sending (local dev / CI).
    Noop,
    /// Deliver via Twilio `SendGrid` Mail Send (`feature = "twilio"`).
    #[cfg(feature = "twilio")]
    Twilio,
}

impl EmailDriver {
    /// Resolve driver from environment (host helper).
    ///
    /// - If `UF_EMAIL_DRIVER` is set to a non-empty value, it wins.
    /// - Otherwise, if `UF_SMTP_HOST` is unset or empty, defaults to [`Noop`](Self::Noop)
    ///   so local runs and E2E do not block on a missing relay (production should set host + driver).
    /// - If a host is configured but the driver is unset, defaults to SMTP.
    pub fn from_env() -> Result<Self, EmailDeliveryError> {
        if let Ok(raw) = std::env::var(EMAIL_DRIVER_ENV) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                return trimmed.parse();
            }
        }
        let host = std::env::var("UF_SMTP_HOST").unwrap_or_default();
        if host.trim().is_empty() {
            Ok(Self::Noop)
        } else {
            Ok(Self::Smtp)
        }
    }

    /// Canonical string form of this driver (see [`EMAIL_DRIVER_SMTP`] etc).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Smtp => EMAIL_DRIVER_SMTP,
            Self::DirectMx => EMAIL_DRIVER_DIRECT_MX,
            Self::Noop => EMAIL_DRIVER_NOOP,
            #[cfg(feature = "twilio")]
            Self::Twilio => EMAIL_DRIVER_TWILIO,
        }
    }
}

impl std::str::FromStr for EmailDriver {
    type Err = EmailDeliveryError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            EMAIL_DRIVER_SMTP => Ok(Self::Smtp),
            EMAIL_DRIVER_DIRECT_MX | "direct-mx" => Ok(Self::DirectMx),
            EMAIL_DRIVER_NOOP | "none" | "off" => Ok(Self::Noop),
            #[cfg(feature = "twilio")]
            EMAIL_DRIVER_TWILIO => Ok(Self::Twilio),
            other => {
                #[cfg(feature = "twilio")]
                let supported = format!(
                    "{EMAIL_DRIVER_SMTP}, {EMAIL_DRIVER_DIRECT_MX}, {EMAIL_DRIVER_NOOP}, {EMAIL_DRIVER_TWILIO}"
                );
                #[cfg(not(feature = "twilio"))]
                let supported =
                    format!("{EMAIL_DRIVER_SMTP}, {EMAIL_DRIVER_DIRECT_MX}, {EMAIL_DRIVER_NOOP}");
                Err(EmailDeliveryError::config(
                    "unsupported_driver",
                    format!("Unsupported email driver '{other}'. Supported values: {supported}"),
                ))
            }
        }
    }
}

/// One lock for every test that sets or clears `UF_SMTP_*` / `UF_EMAIL_*` process env vars.
#[cfg(test)]
pub static EMAIL_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn from_env_uses_smtp_host_when_driver_unset() {
        let _g = EMAIL_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev_driver = std::env::var(EMAIL_DRIVER_ENV).ok();
        let prev_host = std::env::var("UF_SMTP_HOST").ok();
        std::env::remove_var(EMAIL_DRIVER_ENV);
        std::env::remove_var("UF_SMTP_HOST");
        assert!(matches!(EmailDriver::from_env(), Ok(EmailDriver::Noop)));
        std::env::set_var("UF_SMTP_HOST", "smtp.example.test");
        assert!(matches!(EmailDriver::from_env(), Ok(EmailDriver::Smtp)));
        match prev_driver {
            Some(ref v) => std::env::set_var(EMAIL_DRIVER_ENV, v),
            None => std::env::remove_var(EMAIL_DRIVER_ENV),
        }
        match prev_host {
            Some(ref v) => std::env::set_var("UF_SMTP_HOST", v),
            None => std::env::remove_var("UF_SMTP_HOST"),
        }
    }

    #[test]
    fn from_env_noop_when_host_empty_happy_path() {
        let _g = EMAIL_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev_driver = std::env::var(EMAIL_DRIVER_ENV).ok();
        let prev_host = std::env::var("UF_SMTP_HOST").ok();
        std::env::remove_var(EMAIL_DRIVER_ENV);
        std::env::set_var("UF_SMTP_HOST", "   ");
        assert!(matches!(EmailDriver::from_env(), Ok(EmailDriver::Noop)));
        match prev_driver {
            Some(ref v) => std::env::set_var(EMAIL_DRIVER_ENV, v),
            None => std::env::remove_var(EMAIL_DRIVER_ENV),
        }
        match prev_host {
            Some(ref v) => std::env::set_var("UF_SMTP_HOST", v),
            None => std::env::remove_var("UF_SMTP_HOST"),
        }
    }

    #[test]
    fn parses_supported_driver() {
        assert!(matches!("smtp".parse(), Ok(EmailDriver::Smtp)));
        assert!(matches!("SMTP".parse(), Ok(EmailDriver::Smtp)));
        assert!(matches!("direct_mx".parse(), Ok(EmailDriver::DirectMx)));
        assert!(matches!("direct-mx".parse(), Ok(EmailDriver::DirectMx)));
        assert!(matches!("noop".parse(), Ok(EmailDriver::Noop)));
        assert!(matches!("NONE".parse(), Ok(EmailDriver::Noop)));
    }

    #[cfg(feature = "twilio")]
    #[test]
    fn parses_twilio_driver_happy_path() {
        assert!(matches!("twilio".parse(), Ok(EmailDriver::Twilio)));
        assert!(matches!("TWILIO".parse(), Ok(EmailDriver::Twilio)));
    }

    #[test]
    fn rejects_unknown_driver() {
        match "unknown".parse::<EmailDriver>() {
            Err(error) => {
                assert!(error.to_string().contains("Unsupported email driver"));
                assert!(error.to_string().contains("noop"));
                assert!(error
                    .to_string()
                    .contains("reason_class=unsupported_driver"));
            }
            Ok(_) => panic!("expected unsupported driver error"),
        }
    }

    #[cfg(not(feature = "twilio"))]
    #[test]
    fn rejects_twilio_driver_without_feature_sad() {
        match "twilio".parse::<EmailDriver>() {
            Err(error) => {
                assert!(error
                    .to_string()
                    .contains("reason_class=unsupported_driver"));
            }
            Ok(_) => panic!("twilio requires feature"),
        }
    }
}
