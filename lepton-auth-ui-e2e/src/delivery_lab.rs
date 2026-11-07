//! In-memory [`DeliverySettingsBackend`] for the Playwright host.
//!
//! It stands in for a Neutrino-backed host: settings and secrets live in process
//! memory, a save rebuilds the service through [`lepton_auth::delivery_settings`] and
//! swaps it into the live [`LeptonAuthServices`] with no restart, and only users the
//! seed route registers may read or change anything. Text messages go to the lab
//! HTTP sink instead of Twilio so no test reaches a provider; the Twilio fields and
//! secret still go through the real validation.

// Short critical sections over plain data; no lock is held across an await.
#![allow(clippy::significant_drop_tightening)]

use std::collections::HashSet;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use async_trait::async_trait;
use chrono::Utc;
use lepton_auth::delivery_settings::{
    build_email_service, DeliveryError, DeliverySettingsBackend, DeliverySettingsView,
    EmailCandidate, EmailDriverChoice, OAuthCandidate, SecretStatus, SmsCandidate, SmsMode,
};
use lepton_auth::services::LeptonAuthServices;
use lepton_sms::{HttpCaptureSmsConfig, SmsDeliveryService, SmsServiceBuilder};
use lepton_smtp::EmailDeliveryService;
use valence::Valence;

use crate::boot::lab_env;

/// Settings state behind the lab page.
#[derive(Default)]
struct State {
    view: DeliverySettingsView,
    smtp_password: Option<String>,
    sendgrid_api_key: Option<String>,
    twilio_api_secret: Option<String>,
}

/// Lab backend: permission set, saved settings, and the services to swap.
pub struct LabDelivery {
    services: Arc<LeptonAuthServices>,
    initial_email: Arc<dyn EmailDeliveryService>,
    initial_sms: Arc<dyn SmsDeliveryService>,
    allowed: Mutex<HashSet<String>>,
    state: Mutex<State>,
}

static LAB: OnceLock<LabDelivery> = OnceLock::new();

/// Install the lab backend once at boot. `initial_*` are the adapters the host
/// started with; [`LabDelivery::reset`] puts them back.
///
/// # Errors
///
/// When already installed.
pub fn install(
    services: Arc<LeptonAuthServices>,
    initial_email: Arc<dyn EmailDeliveryService>,
    initial_sms: Arc<dyn SmsDeliveryService>,
) -> anyhow::Result<()> {
    LAB.set(LabDelivery {
        services,
        initial_email,
        initial_sms,
        allowed: Mutex::default(),
        state: Mutex::default(),
    })
    .map_err(|_| anyhow::anyhow!("delivery lab already installed"))
}

/// The installed lab backend.
///
/// # Errors
///
/// [`DeliveryError::Store`] when the host did not call [`install`].
pub fn lab() -> Result<&'static LabDelivery, DeliveryError> {
    LAB.get().ok_or(DeliveryError::Store)
}

fn bare(id: &str) -> &str {
    id.split_once(':').map_or(id, |(_, b)| b)
}

fn status() -> SecretStatus {
    SecretStatus {
        is_set: true,
        rotated_at: Some(Utc::now()),
    }
}

impl LabDelivery {
    /// Let a bare user id read and change delivery settings.
    pub fn allow(&self, user_id: &str) {
        self.allowed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(bare(user_id).to_owned());
    }

    fn require(&self, v: &Valence) -> Result<(), DeliveryError> {
        let id = v.actor().user_id().unwrap_or_default();
        let ok = self
            .allowed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(bare(id));
        if ok {
            Ok(())
        } else {
            Err(DeliveryError::PermissionDenied)
        }
    }

    /// Put the boot adapters back and clear saved settings (test cleanup).
    ///
    /// # Errors
    ///
    /// [`DeliveryError::Invalid`] when the services are not swappable.
    pub fn reset(&self) -> Result<(), DeliveryError> {
        let bad = |_| DeliveryError::Invalid {
            field: "services",
            reason: "are not swappable",
        };
        self.services
            .replace_email(Arc::clone(&self.initial_email))
            .map_err(bad)?;
        self.services
            .replace_sms(Arc::clone(&self.initial_sms))
            .map_err(bad)?;
        *self.state.lock().unwrap_or_else(PoisonError::into_inner) = State::default();
        Ok(())
    }

    /// One line the page prints: drivers, revision and secret rotations.
    fn summary(&self) -> String {
        let s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        format!(
            "email={} sms={} revision={}",
            self.services.email.driver().as_str(),
            self.services.sms.driver_name(),
            s.view.revision
        )
    }

    /// Summary line for an authorized actor.
    ///
    /// # Errors
    ///
    /// [`DeliveryError::PermissionDenied`] for anyone not registered.
    pub fn summary_for(&self, v: &Valence) -> Result<String, DeliveryError> {
        self.require(v)?;
        Ok(self.summary())
    }
}

#[async_trait]
impl DeliverySettingsBackend for LabDelivery {
    async fn view(&self, v: &Valence) -> Result<DeliverySettingsView, DeliveryError> {
        self.require(v)?;
        Ok(self
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .view
            .clone())
    }

    async fn test_email(&self, v: &Valence, c: &EmailCandidate) -> Result<(), DeliveryError> {
        self.require(v)?;
        c.validate()
    }

    async fn test_sms(&self, v: &Valence, c: &SmsCandidate) -> Result<(), DeliveryError> {
        self.require(v)?;
        c.validate()
    }

    async fn save_email(&self, v: &Valence, c: EmailCandidate) -> Result<(), DeliveryError> {
        self.require(v)?;
        let (mut pw, mut key) = {
            let s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            (s.smtp_password.clone(), s.sendgrid_api_key.clone())
        };
        if let Some(new) = c.smtp_password.as_ref().filter(|s| !s.is_empty()) {
            pw = Some(new.expose_secret().to_owned());
        }
        if let Some(new) = c.sendgrid_api_key.as_ref().filter(|s| !s.is_empty()) {
            key = Some(new.expose_secret().to_owned());
        }
        // Build first: a candidate that does not build leaves the live service and
        // the saved state untouched.
        let next = build_email_service(&c, pw.as_deref(), key.as_deref())?;
        self.services
            .replace_email(next)
            .map_err(|_| DeliveryError::Invalid {
                field: "email",
                reason: "service is not swappable",
            })?;
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        s.view.revision += 1;
        s.view.email.driver = c.driver;
        s.view.email.smtp_host = c.smtp_host;
        s.view.email.smtp_port = c.smtp_port;
        s.view.email.smtp_tls = c.smtp_tls;
        s.view.email.smtp_username = c.smtp_username;
        s.view.email.from_email = c.from_email;
        s.view.email.from_name = c.from_name;
        if c.smtp_password.is_some_and(|p| !p.is_empty()) {
            s.view.email.smtp_password = status();
        }
        if c.sendgrid_api_key.is_some_and(|p| !p.is_empty()) {
            s.view.email.sendgrid_api_key = status();
        }
        s.smtp_password = pw;
        s.sendgrid_api_key = key;
        Ok(())
    }

    async fn save_sms(&self, v: &Valence, c: SmsCandidate) -> Result<(), DeliveryError> {
        self.require(v)?;
        c.validate()?;
        let rotated = c.twilio_api_secret.as_ref().filter(|s| !s.is_empty());
        let secret_known = rotated.is_some()
            || self
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .twilio_api_secret
                .is_some();
        if c.mode != SmsMode::Off && !secret_known {
            return Err(DeliveryError::Invalid {
                field: "twilio_api_secret",
                reason: "is required",
            });
        }
        let builder = SmsServiceBuilder::new();
        let builder = if c.mode == SmsMode::Off {
            builder.noop()
        } else {
            let sink = lab_env("UF_SMS_SINK_URL", "http://127.0.0.1:8099");
            builder.http_capture(HttpCaptureSmsConfig::new(sink).map_err(|_| {
                DeliveryError::Invalid {
                    field: "sms",
                    reason: "settings are not usable",
                }
            })?)
        };
        let next = builder.build().map_err(|_| DeliveryError::Invalid {
            field: "sms",
            reason: "settings are not usable",
        })?;
        self.services
            .replace_sms(next)
            .map_err(|_| DeliveryError::Invalid {
                field: "sms",
                reason: "service is not swappable",
            })?;
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        s.view.revision += 1;
        s.view.sms.mode = c.mode;
        s.view.sms.twilio_account_sid = c.twilio_account_sid;
        s.view.sms.twilio_api_key_sid = c.twilio_api_key_sid;
        s.view.sms.twilio_verify_service_sid = c.twilio_verify_service_sid;
        s.view.sms.twilio_from = c.twilio_from;
        if let Some(new) = rotated {
            s.twilio_api_secret = Some(new.expose_secret().to_owned());
            s.view.sms.twilio_api_secret = status();
        }
        Ok(())
    }

    async fn save_oauth(&self, v: &Valence, _c: OAuthCandidate) -> Result<(), DeliveryError> {
        self.require(v)?;
        Err(DeliveryError::Invalid {
            field: "oauth",
            reason: "is not part of this lab",
        })
    }

    async fn rotate_totp_key(&self, v: &Valence) -> Result<(), DeliveryError> {
        self.require(v)?;
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        s.view.totp_key.version += 1;
        s.view.totp_key.rotated_at = Some(Utc::now());
        s.view.revision += 1;
        Ok(())
    }
}

/// Email driver for a lab form value: `off`, `smtp`, `sendgrid` or `direct_mx`.
pub fn parse_driver(raw: &str) -> Result<EmailDriverChoice, DeliveryError> {
    match raw.trim() {
        "off" => Ok(EmailDriverChoice::Off),
        "smtp" => Ok(EmailDriverChoice::Smtp),
        "sendgrid" => Ok(EmailDriverChoice::SendGrid),
        "direct_mx" => Ok(EmailDriverChoice::DirectMx),
        _ => Err(DeliveryError::Invalid {
            field: "driver",
            reason: "is not a known driver",
        }),
    }
}

/// Text-message mode for a lab form value: `off`, `verify` or `messages`.
pub fn parse_mode(raw: &str) -> Result<SmsMode, DeliveryError> {
    match raw.trim() {
        "off" => Ok(SmsMode::Off),
        "verify" => Ok(SmsMode::Verify),
        "messages" => Ok(SmsMode::Messages),
        _ => Err(DeliveryError::Invalid {
            field: "mode",
            reason: "is not a known mode",
        }),
    }
}
