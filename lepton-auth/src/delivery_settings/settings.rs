//! Wire types for the "Sign-in and delivery" settings page.
//!
//! These cross the server-function boundary in both directions, so they compile
//! on the client too. Secret values only ever travel *toward* the server, inside
//! [`WriteOnlySecret`]. Nothing in [`DeliverySettingsView`] can carry one.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A secret the operator typed into a form.
///
/// Serializes so it can reach the server, never prints (`Debug` shows a
/// placeholder) and has no `Display`. Read it with [`expose_secret`](Self::expose_secret)
/// at the one place that seals or sends it.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteOnlySecret(String);

impl WriteOnlySecret {
    /// Wrap typed plaintext.
    #[must_use]
    pub fn new(plaintext: impl Into<String>) -> Self {
        Self(plaintext.into())
    }

    /// The plaintext. Call only where the value is sealed or used to send.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// True when the operator left the field empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.trim().is_empty()
    }
}

impl std::fmt::Debug for WriteOnlySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WriteOnlySecret(<redacted>)")
    }
}

/// Whether a secret exists and when it last changed. Never the value.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretStatus {
    /// A sealed value exists under the fixed Neutrino name.
    pub is_set: bool,
    /// When the value was last replaced, when known.
    pub rotated_at: Option<DateTime<Utc>>,
}

/// Which email path is active.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmailDriverChoice {
    /// No email leaves the process.
    #[default]
    Off,
    /// An SMTP relay.
    Smtp,
    /// Twilio `SendGrid` Mail Send.
    SendGrid,
    /// Direct delivery to the recipient's MX hosts, with no relay.
    DirectMx,
}

/// Which text-message path is active.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SmsMode {
    /// No text message leaves the process.
    #[default]
    Off,
    /// Twilio Verify (Twilio sends and checks the code).
    Verify,
    /// Twilio Programmable Messaging (Lepton sends the code in the body).
    Messages,
}

/// Email settings as shown on the page. Secrets appear as [`SecretStatus`] only.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailSettingsView {
    /// Active path.
    pub driver: EmailDriverChoice,
    /// SMTP host.
    pub smtp_host: String,
    /// SMTP port.
    pub smtp_port: u16,
    /// Whether the SMTP connection uses TLS.
    pub smtp_tls: bool,
    /// SMTP username.
    pub smtp_username: String,
    /// `From` address.
    pub from_email: String,
    /// `From` display name.
    pub from_name: String,
    /// SMTP password.
    pub smtp_password: SecretStatus,
    /// `SendGrid` API key.
    pub sendgrid_api_key: SecretStatus,
}

/// Text-message settings as shown on the page.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmsSettingsView {
    /// Active path.
    pub mode: SmsMode,
    /// Twilio account SID (`AC…`).
    pub twilio_account_sid: String,
    /// Twilio API key SID (`SK…`).
    pub twilio_api_key_sid: String,
    /// Twilio Verify service SID (`VA…`).
    pub twilio_verify_service_sid: String,
    /// Sender number for Messages mode.
    pub twilio_from: String,
    /// Twilio API secret.
    pub twilio_api_secret: SecretStatus,
}

/// One OAuth provider row.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthProviderView {
    /// Public client id.
    pub client_id: String,
    /// Client secret.
    pub secret: SecretStatus,
}

/// OAuth provider settings as shown on the page.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthSettingsView {
    /// Google.
    pub google: OAuthProviderView,
    /// GitHub.
    pub github: OAuthProviderView,
}

/// TOTP seal key state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpKeyView {
    /// Current key version new authenticator secrets are sealed with.
    pub version: u32,
    /// When that version was created.
    pub rotated_at: Option<DateTime<Utc>>,
}

/// Everything the page renders. No field can hold a secret value.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliverySettingsView {
    /// Bumped on every save; hosts poll it to notice changes.
    pub revision: i64,
    /// Email.
    pub email: EmailSettingsView,
    /// Text messages.
    pub sms: SmsSettingsView,
    /// OAuth providers.
    pub oauth: OAuthSettingsView,
    /// TOTP seal key.
    pub totp_key: TotpKeyView,
}

/// Email values the operator wants to test or save.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailCandidate {
    /// Active path.
    pub driver: EmailDriverChoice,
    /// SMTP host.
    pub smtp_host: String,
    /// SMTP port.
    pub smtp_port: u16,
    /// Whether the SMTP connection uses TLS.
    pub smtp_tls: bool,
    /// SMTP username.
    pub smtp_username: String,
    /// `From` address.
    pub from_email: String,
    /// `From` display name.
    pub from_name: String,
    /// New SMTP password, only when replacing it.
    pub smtp_password: Option<WriteOnlySecret>,
    /// New `SendGrid` key, only when replacing it.
    pub sendgrid_api_key: Option<WriteOnlySecret>,
    /// Address the test message goes to.
    pub test_recipient: String,
}

/// Text-message values the operator wants to test or save.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmsCandidate {
    /// Active path.
    pub mode: SmsMode,
    /// Twilio account SID.
    pub twilio_account_sid: String,
    /// Twilio API key SID.
    pub twilio_api_key_sid: String,
    /// Twilio Verify service SID.
    pub twilio_verify_service_sid: String,
    /// Sender number for Messages mode.
    pub twilio_from: String,
    /// New API secret, only when replacing it.
    pub twilio_api_secret: Option<WriteOnlySecret>,
    /// E.164 number the test message goes to.
    pub test_recipient: String,
}

/// OAuth values the operator wants to save.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthCandidate {
    /// Google client id (empty turns the provider off).
    pub google_client_id: String,
    /// GitHub client id (empty turns the provider off).
    pub github_client_id: String,
    /// New Google client secret, only when replacing it.
    pub google_client_secret: Option<WriteOnlySecret>,
    /// New GitHub client secret, only when replacing it.
    pub github_client_secret: Option<WriteOnlySecret>,
}

/// Which channel an operation concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Channel {
    /// Email.
    Email,
    /// Text messages.
    Sms,
    /// OAuth providers.
    OAuth,
    /// TOTP seal key.
    TotpKey,
}

impl Channel {
    /// Stable label for tracing and metrics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Sms => "sms",
            Self::OAuth => "oauth",
            Self::TotpKey => "totp_key",
        }
    }
}

/// Why a test send failed, in terms an operator can act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestFailureClass {
    /// Provider rejected the credentials.
    Unauthorized,
    /// Provider does not accept the sender address.
    UnverifiedSender,
    /// Destination number or address is not valid.
    InvalidRecipient,
    /// Provider unreachable or timed out.
    Network,
    /// Anything else.
    Other,
}

impl TestFailureClass {
    /// Stable label for tracing and the page.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::UnverifiedSender => "unverified_sender",
            Self::InvalidRecipient => "invalid_recipient",
            Self::Network => "network",
            Self::Other => "other",
        }
    }
}

/// Failures from reading or changing delivery settings.
///
/// Display carries a stable `reason_class` and a field or operation name, never
/// a secret or a recipient.
#[derive(Clone, Debug, Error, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryError {
    /// The actor lacks `LeptonManageDelivery`.
    #[error("reason_class=permission_denied: not allowed to manage sign-in and delivery")]
    PermissionDenied,
    /// A fresh authenticator code is required first.
    #[error("reason_class=step_up_required: recent totp verification required")]
    StepUpRequired,
    /// A submitted value failed validation.
    #[error("reason_class=invalid: {field} {reason}")]
    Invalid {
        /// Field name, never its value.
        field: &'static str,
        /// What is wrong.
        reason: &'static str,
    },
    /// The provider rejected the test message.
    #[error("reason_class=test_send_failed: {} test send failed ({})", channel.as_str(), class.as_str())]
    TestSendFailed {
        /// Channel tested.
        channel: Channel,
        /// Actionable class.
        class: TestFailureClass,
    },
    /// The secret vault refused or failed an operation.
    #[error("reason_class=secret_store: {operation} failed")]
    SecretStore {
        /// Operation name.
        operation: &'static str,
    },
    /// Secrets were written but the settings row was not; retry the save.
    #[error("reason_class=save_not_applied: secrets updated, settings not saved; retry")]
    SaveNotApplied,
    /// Valence persistence failed.
    #[error("reason_class=store: settings store failed")]
    Store,
}

impl DeliveryError {
    /// Stable reason class for logs, metrics and UI mapping.
    #[must_use]
    pub const fn reason_class(&self) -> &'static str {
        match self {
            Self::PermissionDenied => "permission_denied",
            Self::StepUpRequired => "step_up_required",
            Self::Invalid { .. } => "invalid",
            Self::TestSendFailed { .. } => "test_send_failed",
            Self::SecretStore { .. } => "secret_store",
            Self::SaveNotApplied => "save_not_applied",
            Self::Store => "store",
        }
    }
}

fn require_nonblank(value: &str, field: &'static str) -> Result<(), DeliveryError> {
    if value.trim().is_empty() {
        return Err(DeliveryError::Invalid {
            field,
            reason: "is required",
        });
    }
    Ok(())
}

fn require_prefix(value: &str, prefix: &str, field: &'static str) -> Result<(), DeliveryError> {
    require_nonblank(value, field)?;
    if !value.trim().starts_with(prefix) {
        return Err(DeliveryError::Invalid {
            field,
            reason: "has the wrong format",
        });
    }
    Ok(())
}

fn require_email(value: &str, field: &'static str) -> Result<(), DeliveryError> {
    require_nonblank(value, field)?;
    let trimmed = value.trim();
    let ok = trimmed
        .split_once('@')
        .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'));
    if !ok {
        return Err(DeliveryError::Invalid {
            field,
            reason: "is not an email address",
        });
    }
    Ok(())
}

fn require_e164(value: &str, field: &'static str) -> Result<(), DeliveryError> {
    let trimmed = value.trim();
    let digits = trimmed.strip_prefix('+').unwrap_or("");
    let ok = (2..=15).contains(&digits.len())
        && digits.chars().all(|c| c.is_ascii_digit())
        && !digits.starts_with('0');
    if !ok {
        return Err(DeliveryError::Invalid {
            field,
            reason: "must be an E.164 number",
        });
    }
    Ok(())
}

impl EmailCandidate {
    /// Check the values a save or test needs for the chosen driver.
    ///
    /// # Errors
    ///
    /// [`DeliveryError::Invalid`] naming the first bad field.
    pub fn validate(&self) -> Result<(), DeliveryError> {
        match self.driver {
            EmailDriverChoice::Off => return Ok(()),
            EmailDriverChoice::Smtp => {
                require_nonblank(&self.smtp_host, "smtp_host")?;
                if self.smtp_port == 0 {
                    return Err(DeliveryError::Invalid {
                        field: "smtp_port",
                        reason: "must be between 1 and 65535",
                    });
                }
            }
            EmailDriverChoice::SendGrid | EmailDriverChoice::DirectMx => {}
        }
        require_email(&self.from_email, "from_email")?;
        require_email(&self.test_recipient, "test_recipient")
    }
}

impl SmsCandidate {
    /// Check the values a save or test needs for the chosen mode.
    ///
    /// # Errors
    ///
    /// [`DeliveryError::Invalid`] naming the first bad field.
    pub fn validate(&self) -> Result<(), DeliveryError> {
        match self.mode {
            SmsMode::Off => return Ok(()),
            SmsMode::Verify => {
                require_prefix(&self.twilio_account_sid, "AC", "twilio_account_sid")?;
                require_prefix(&self.twilio_api_key_sid, "SK", "twilio_api_key_sid")?;
                require_prefix(
                    &self.twilio_verify_service_sid,
                    "VA",
                    "twilio_verify_service_sid",
                )?;
            }
            SmsMode::Messages => {
                require_prefix(&self.twilio_account_sid, "AC", "twilio_account_sid")?;
                require_prefix(&self.twilio_api_key_sid, "SK", "twilio_api_key_sid")?;
                require_e164(&self.twilio_from, "twilio_from")?;
            }
        }
        require_e164(&self.test_recipient, "test_recipient")
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn smtp() -> EmailCandidate {
        EmailCandidate {
            driver: EmailDriverChoice::Smtp,
            smtp_host: "smtp.example.test".into(),
            smtp_port: 587,
            smtp_tls: true,
            from_email: "cell@example.test".into(),
            test_recipient: "ops@example.test".into(),
            ..EmailCandidate::default()
        }
    }

    fn verify() -> SmsCandidate {
        SmsCandidate {
            mode: SmsMode::Verify,
            twilio_account_sid: "ACxxxxxxxx".into(),
            twilio_api_key_sid: "SKxxxxxxxx".into(),
            twilio_verify_service_sid: "VAxxxxxxxx".into(),
            test_recipient: "+15550100".into(),
            ..SmsCandidate::default()
        }
    }

    #[test]
    fn write_only_secret_never_prints() {
        let s = WriteOnlySecret::new("hunter2-very-secret");
        assert!(!format!("{s:?}").contains("hunter2"));
        let c = EmailCandidate {
            smtp_password: Some(s),
            ..smtp()
        };
        assert!(!format!("{c:?}").contains("hunter2"));
    }

    #[test]
    fn view_serializes_without_any_secret_value_keys() {
        let view = DeliverySettingsView {
            email: EmailSettingsView {
                smtp_password: SecretStatus {
                    is_set: true,
                    rotated_at: None,
                },
                ..EmailSettingsView::default()
            },
            ..DeliverySettingsView::default()
        };
        let json = serde_json::to_string(&view).unwrap();
        // The only secret-shaped keys are status objects with is_set / rotated_at.
        for needle in ["\"password\"", "\"api_key\":\"", "\"secret\":\""] {
            assert!(!json.contains(needle), "{needle} leaked in {json}");
        }
        assert!(json.contains("\"is_set\":true"));
    }

    #[test]
    fn email_validate_happy_and_off_skips_checks() {
        smtp().validate().expect("valid smtp");
        EmailCandidate::default()
            .validate()
            .expect("off needs nothing");
    }

    #[test]
    fn email_validate_rejects_bad_fields_sad() {
        let mut c = smtp();
        c.smtp_port = 0;
        assert_eq!(
            c.validate().unwrap_err(),
            DeliveryError::Invalid {
                field: "smtp_port",
                reason: "must be between 1 and 65535"
            }
        );
        let mut c = smtp();
        c.smtp_host = "  ".into();
        assert!(matches!(
            c.validate().unwrap_err(),
            DeliveryError::Invalid {
                field: "smtp_host",
                ..
            }
        ));
        let mut c = smtp();
        c.from_email = "not-an-address".into();
        assert!(matches!(
            c.validate().unwrap_err(),
            DeliveryError::Invalid {
                field: "from_email",
                ..
            }
        ));
    }

    #[test]
    fn sms_validate_checks_sid_prefixes_and_e164_sad() {
        verify().validate().expect("valid verify");
        let mut c = verify();
        c.twilio_account_sid = "XXabc".into();
        assert!(matches!(
            c.validate().unwrap_err(),
            DeliveryError::Invalid {
                field: "twilio_account_sid",
                ..
            }
        ));
        let mut c = verify();
        c.test_recipient = "5550100".into();
        assert!(matches!(
            c.validate().unwrap_err(),
            DeliveryError::Invalid {
                field: "test_recipient",
                ..
            }
        ));
        let mut c = verify();
        c.mode = SmsMode::Messages;
        c.twilio_from = String::new();
        assert!(matches!(
            c.validate().unwrap_err(),
            DeliveryError::Invalid {
                field: "twilio_from",
                ..
            }
        ));
    }

    #[test]
    fn errors_carry_class_not_values() {
        let e = DeliveryError::TestSendFailed {
            channel: Channel::Sms,
            class: TestFailureClass::Unauthorized,
        };
        assert_eq!(e.reason_class(), "test_send_failed");
        assert!(e.to_string().contains("unauthorized"));
        assert!(DeliveryError::SecretStore {
            operation: "rotate"
        }
        .to_string()
        .contains("rotate"));
    }
}
