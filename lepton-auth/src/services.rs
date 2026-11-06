//! Injected auth delivery services (email / SMS / public base URL).
//!
//! Hosts call [`provide_auth_services`] once during SSR boot. Send paths and
//! helpers then read the bundle with [`auth_services`]. Missing context returns
//! [`LeptonAuthServicesError::NotInContext`]. Send paths do not rebuild services
//! from process environment — build the bundle with [`LeptonAuthServicesBuilder`]
//! at boot (and optional [`lepton_smtp::EmailServiceBuilder::from_env`] for mail).
//!
//! Injects Leptos context for delivery adapters, public base URL, and optional OAuth /
//! `WebAuthn` RP config. SMTP/SMS transport comes from `lepton-smtp` / `lepton-sms`;
//! secret resolution and OAuth provider HTTP stay outside this module ([`crate::oauth`]).
//!
//! Channel fields are compile-time: `email` / `phone` features omit unused adapters.
//!
//! # When to call
//!
//! | Task | API |
//! |------|-----|
//! | Build bundle | [`LeptonAuthServicesBuilder`] |
//! | Provide once at SSR boot | [`provide_auth_services`] |
//! | Extract in server fns | [`auth_services`] |
//!
//! Hosts resolve secrets outside this crate (plain strings). SMS: [`lepton_sms`]
//! (Noop / Test; optional live Twilio via that crate's `twilio` feature).
//!
//! # Examples
//!
//! Provide a noop email adapter at boot (`email` feature):
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use lepton_auth::services::{provide_auth_services, LeptonAuthServicesBuilder};
//! use lepton_smtp::EmailServiceBuilder;
//!
//! let email = EmailServiceBuilder::new().noop().build()?;
//! provide_auth_services(Arc::new(
//!     LeptonAuthServicesBuilder::new()
//!         .email(email)
//!         .public_base_url("http://127.0.0.1:3000")
//!         .build()?,
//! ));
//! ```
//!
//! Extract in a server fn (after provide):
//!
//! ```rust,ignore
//! use lepton_auth::services::auth_services;
//!
//! let services = auth_services()?;
//! let _base = &services.public_base_url;
//! ```
//!
//! # Further reading
//!
//! Crate-root [Boot delivery](crate#boot-delivery-email-only). Runnable SMTP smoke:
//! `examples/auth_flows_noop_smtp` (envelopes + adapters; does not call
//! [`provide_auth_services`]).

#[cfg(feature = "ssr")]
use std::sync::{Arc, PoisonError, RwLock};

#[cfg(all(feature = "ssr", feature = "phone"))]
use lepton_sms::SmsDeliveryService;
#[cfg(all(feature = "ssr", feature = "email"))]
use lepton_smtp::EmailDeliveryService;
#[cfg(feature = "ssr")]
use thiserror::Error;

#[cfg(all(feature = "ssr", feature = "email"))]
use crate::delivery_settings::SwappableEmail;
#[cfg(all(feature = "ssr", feature = "phone"))]
use crate::delivery_settings::SwappableSms;
#[cfg(all(feature = "ssr", feature = "webauthn"))]
use crate::devices::WebauthnRpConfig;
#[cfg(feature = "ssr")]
use crate::oauth::OAuthClientConfig;

/// Shared, replaceable OAuth client configuration.
///
/// Clones share one slot, so a host that keeps a clone can [`set`](Self::set) new
/// provider settings and every later `begin`/`complete` call sees them without a
/// restart. Readers take a snapshot with [`get`](Self::get).
#[cfg(feature = "ssr")]
#[derive(Clone, Default)]
pub struct OAuthHandle {
    slot: Arc<RwLock<Option<Arc<OAuthClientConfig>>>>,
}

#[cfg(feature = "ssr")]
impl OAuthHandle {
    /// Handle holding `cfg` (or nothing, when OAuth is not configured).
    #[must_use]
    pub fn new(cfg: Option<OAuthClientConfig>) -> Self {
        Self {
            slot: Arc::new(RwLock::new(cfg.map(Arc::new))),
        }
    }

    /// Current configuration, or `None` when OAuth is not configured.
    #[must_use]
    pub fn get(&self) -> Option<Arc<OAuthClientConfig>> {
        self.slot
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Replace the configuration. `None` turns OAuth off.
    pub fn set(&self, cfg: Option<OAuthClientConfig>) {
        *self.slot.write().unwrap_or_else(PoisonError::into_inner) = cfg.map(Arc::new);
    }
}

/// Bundled delivery adapters + public URL used by auth verification flows.
#[cfg(feature = "ssr")]
#[derive(Clone)]
pub struct LeptonAuthServices {
    /// Transactional email adapter (`email` feature).
    #[cfg(feature = "email")]
    pub email: Arc<dyn EmailDeliveryService>,
    /// SMS adapter (`phone` feature).
    #[cfg(feature = "phone")]
    pub sms: Arc<dyn SmsDeliveryService>,
    /// Absolute public origin for token links (no trailing slash required).
    pub public_base_url: String,
    /// OAuth client config (Google/GitHub / mock). Empty when the host omits `.oauth()`.
    ///
    /// Read with [`OAuthHandle::get`]; hosts that keep a clone of the handle can
    /// replace the configuration while the process runs.
    pub oauth: OAuthHandle,
    /// Optional `WebAuthn` relying-party config. Absent when host omits `.webauthn_rp()`.
    #[cfg(feature = "webauthn")]
    pub webauthn_rp: Option<WebauthnRpConfig>,
    /// Swap handle behind `email`; set by [`LeptonAuthServicesBuilder::email_swappable`].
    #[cfg(feature = "email")]
    email_swap: Option<Arc<SwappableEmail>>,
    /// Swap handle behind `sms`; set by [`LeptonAuthServicesBuilder::sms_swappable`].
    #[cfg(feature = "phone")]
    sms_swap: Option<Arc<SwappableSms>>,
}

/// Builder for [`LeptonAuthServices`].
#[cfg(feature = "ssr")]
#[derive(Default)]
pub struct LeptonAuthServicesBuilder {
    #[cfg(feature = "email")]
    email: Option<Arc<dyn EmailDeliveryService>>,
    #[cfg(feature = "phone")]
    sms: Option<Arc<dyn SmsDeliveryService>>,
    public_base_url: Option<String>,
    oauth: OAuthHandle,
    #[cfg(feature = "webauthn")]
    webauthn_rp: Option<WebauthnRpConfig>,
    #[cfg(feature = "email")]
    email_swap: Option<Arc<SwappableEmail>>,
    #[cfg(feature = "phone")]
    sms_swap: Option<Arc<SwappableSms>>,
}

/// Errors from resolving or building [`LeptonAuthServices`].
#[cfg(feature = "ssr")]
#[derive(Debug, Error)]
pub enum LeptonAuthServicesError {
    /// [`auth_services`] was called without a prior [`provide_auth_services`].
    #[error("LeptonAuthServices not in Leptos context (provide_auth_services at host boot)")]
    NotInContext,
    /// Email builder / config failure.
    #[cfg(feature = "email")]
    #[error("email service: {0}")]
    Email(#[from] lepton_smtp::EmailDeliveryError),
    /// SMS builder / config failure.
    #[cfg(feature = "phone")]
    #[error("sms service: {0}")]
    Sms(#[from] lepton_sms::SmsDeliveryError),
    /// The bundle was built with a fixed adapter, so it cannot swap one in.
    #[cfg(any(feature = "email", feature = "phone"))]
    #[error("{channel} service was not built swappable (use the *_swappable builder method)")]
    NotSwappable {
        /// `email` or `sms`.
        channel: &'static str,
    },
}

#[cfg(feature = "ssr")]
impl LeptonAuthServicesBuilder {
    /// Empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the email delivery adapter (`email` feature).
    #[cfg(feature = "email")]
    #[must_use]
    pub fn email(mut self, email: Arc<dyn EmailDeliveryService>) -> Self {
        self.email = Some(email);
        self.email_swap = None;
        self
    }

    /// Set the SMS delivery adapter (`phone` feature).
    #[cfg(feature = "phone")]
    #[must_use]
    pub fn sms(mut self, sms: Arc<dyn SmsDeliveryService>) -> Self {
        self.sms = Some(sms);
        self.sms_swap = None;
        self
    }

    /// Set the email adapter behind a [`SwappableEmail`], so
    /// [`LeptonAuthServices::replace_email`] can change it while the process runs.
    #[cfg(feature = "email")]
    #[must_use]
    pub fn email_swappable(mut self, initial: Arc<dyn EmailDeliveryService>) -> Self {
        let swap = Arc::new(SwappableEmail::new(initial));
        self.email = Some(swap.clone());
        self.email_swap = Some(swap);
        self
    }

    /// Set the SMS adapter behind a [`SwappableSms`], so
    /// [`LeptonAuthServices::replace_sms`] can change it while the process runs.
    #[cfg(feature = "phone")]
    #[must_use]
    pub fn sms_swappable(mut self, initial: Arc<dyn SmsDeliveryService>) -> Self {
        let swap = Arc::new(SwappableSms::new(initial));
        self.sms = Some(swap.clone());
        self.sms_swap = Some(swap);
        self
    }

    /// Set the public base URL used for token-bearing links.
    #[must_use]
    pub fn public_base_url(mut self, url: impl Into<String>) -> Self {
        self.public_base_url = Some(url.into());
        self
    }

    /// Attach OAuth client configuration (optional; enables `BeginOAuth` / callback).
    #[must_use]
    pub fn oauth(mut self, cfg: OAuthClientConfig) -> Self {
        self.oauth = OAuthHandle::new(Some(cfg));
        self
    }

    /// Attach a shared [`OAuthHandle`] so the host can change OAuth settings after boot.
    #[must_use]
    pub fn oauth_handle(mut self, handle: OAuthHandle) -> Self {
        self.oauth = handle;
        self
    }

    /// Attach `WebAuthn` relying-party configuration (optional; enables passkey server fns).
    #[cfg(feature = "webauthn")]
    #[must_use]
    pub fn webauthn_rp(mut self, cfg: WebauthnRpConfig) -> Self {
        self.webauthn_rp = Some(cfg);
        self
    }

    /// Build [`LeptonAuthServices`].
    ///
    /// # Errors
    ///
    /// Returns [`LeptonAuthServicesError`] when a required channel adapter is missing.
    pub fn build(self) -> Result<LeptonAuthServices, LeptonAuthServicesError> {
        #[cfg(feature = "email")]
        let email = self.email.ok_or_else(|| {
            LeptonAuthServicesError::Email(lepton_smtp::EmailDeliveryError::ConfigError(
                "reason_class=missing_email: LeptonAuthServicesBuilder requires email()".into(),
            ))
        })?;
        #[cfg(feature = "phone")]
        let sms = self.sms.ok_or_else(|| {
            LeptonAuthServicesError::Sms(lepton_sms::SmsDeliveryError::ConfigError(
                "reason_class=missing_sms: LeptonAuthServicesBuilder requires sms()".into(),
            ))
        })?;
        let public_base_url = self
            .public_base_url
            .unwrap_or_else(|| "http://127.0.0.1:3000".to_string());
        Ok(LeptonAuthServices {
            #[cfg(feature = "email")]
            email,
            #[cfg(feature = "phone")]
            sms,
            public_base_url,
            oauth: self.oauth,
            #[cfg(feature = "webauthn")]
            webauthn_rp: self.webauthn_rp,
            #[cfg(feature = "email")]
            email_swap: self.email_swap,
            #[cfg(feature = "phone")]
            sms_swap: self.sms_swap,
        })
    }
}

#[cfg(feature = "ssr")]
impl LeptonAuthServices {
    /// Return the configured `WebAuthn` RP, or a config error when missing.
    ///
    /// # Errors
    ///
    /// [`crate::devices::DeviceError::Config`] when the host did not call
    /// [`LeptonAuthServicesBuilder::webauthn_rp`].
    #[cfg(feature = "webauthn")]
    pub fn require_webauthn_rp(&self) -> Result<&WebauthnRpConfig, crate::devices::DeviceError> {
        self.webauthn_rp
            .as_ref()
            .ok_or(crate::devices::DeviceError::Config)
    }
}

#[cfg(feature = "ssr")]
impl LeptonAuthServices {
    /// Route later email sends through `next`. Sends already in flight finish on the
    /// previous adapter.
    ///
    /// # Errors
    ///
    /// [`LeptonAuthServicesError::NotSwappable`] unless the bundle was built with
    /// [`LeptonAuthServicesBuilder::email_swappable`].
    #[cfg(feature = "email")]
    pub fn replace_email(
        &self,
        next: Arc<dyn EmailDeliveryService>,
    ) -> Result<(), LeptonAuthServicesError> {
        let swap = self
            .email_swap
            .as_ref()
            .ok_or(LeptonAuthServicesError::NotSwappable { channel: "email" })?;
        swap.swap(next);
        Ok(())
    }

    /// Route later SMS sends through `next`. Sends already in flight finish on the
    /// previous adapter.
    ///
    /// # Errors
    ///
    /// [`LeptonAuthServicesError::NotSwappable`] unless the bundle was built with
    /// [`LeptonAuthServicesBuilder::sms_swappable`].
    #[cfg(feature = "phone")]
    pub fn replace_sms(
        &self,
        next: Arc<dyn SmsDeliveryService>,
    ) -> Result<(), LeptonAuthServicesError> {
        let swap = self
            .sms_swap
            .as_ref()
            .ok_or(LeptonAuthServicesError::NotSwappable { channel: "sms" })?;
        swap.swap(next);
        Ok(())
    }

    /// Rebuild the email service from saved settings and swap it in, with no restart.
    /// A candidate that does not build leaves the current service in place.
    ///
    /// # Errors
    ///
    /// [`DeliveryError::Invalid`](crate::delivery_settings::DeliveryError::Invalid) when the settings do not build or the bundle is not
    /// swappable.
    #[cfg(feature = "email")]
    pub fn apply_email_settings(
        &self,
        candidate: &crate::delivery_settings::EmailCandidate,
        smtp_password: Option<&str>,
        sendgrid_api_key: Option<&str>,
    ) -> Result<(), crate::delivery_settings::DeliveryError> {
        let next = crate::delivery_settings::build_email_service(
            candidate,
            smtp_password,
            sendgrid_api_key,
        )?;
        // Deliberate: `DeliveryError` is the settings-page wire type and has no variant for a
        // host wiring mistake. Callers that must tell the two apart use `replace_email`,
        // which returns `NotSwappable`.
        self.replace_email(next)
            .map_err(|_| crate::delivery_settings::DeliveryError::Invalid {
                field: "email",
                reason: "service is not swappable",
            })
    }

    /// Rebuild the SMS service from saved settings and swap it in, with no restart.
    /// A candidate that does not build leaves the current service in place.
    ///
    /// # Errors
    ///
    /// [`DeliveryError::Invalid`](crate::delivery_settings::DeliveryError::Invalid) when the settings do not build or the bundle is not
    /// swappable.
    #[cfg(feature = "phone")]
    pub fn apply_sms_settings(
        &self,
        candidate: &crate::delivery_settings::SmsCandidate,
        twilio_api_secret: Option<&str>,
    ) -> Result<(), crate::delivery_settings::DeliveryError> {
        let next = crate::delivery_settings::build_sms_service(candidate, twilio_api_secret)?;
        // Deliberate: `DeliveryError` is the settings-page wire type and has no variant for a
        // host wiring mistake. Callers that must tell the two apart use `replace_sms`,
        // which returns `NotSwappable`.
        self.replace_sms(next)
            .map_err(|_| crate::delivery_settings::DeliveryError::Invalid {
                field: "sms",
                reason: "service is not swappable",
            })
    }
}

/// Insert [`LeptonAuthServices`] into the current Leptos reactive owner / request context.
///
/// Call once at SSR boot (or at the start of a test owner). See module examples.
#[cfg(feature = "ssr")]
pub fn provide_auth_services(services: Arc<LeptonAuthServices>) {
    leptos::prelude::provide_context(services);
}

/// Return the [`LeptonAuthServices`] previously inserted with [`provide_auth_services`].
///
/// When nothing was provided, returns [`LeptonAuthServicesError::NotInContext`].
/// Send paths do not rebuild the bundle from process environment.
///
/// # Errors
///
/// [`LeptonAuthServicesError::NotInContext`] when nothing was provided.
#[cfg(feature = "ssr")]
pub fn auth_services() -> Result<Arc<LeptonAuthServices>, LeptonAuthServicesError> {
    leptos::prelude::use_context::<Arc<LeptonAuthServices>>()
        .ok_or(LeptonAuthServicesError::NotInContext)
}

#[cfg(all(test, feature = "ssr"))]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn auth_services_missing_context_sad() {
        assert!(matches!(
            auth_services(),
            Err(LeptonAuthServicesError::NotInContext)
        ));
    }

    #[cfg(all(not(feature = "email"), not(feature = "phone")))]
    #[test]
    fn services_ssr_only_build_happy_path() {
        let services = LeptonAuthServicesBuilder::new()
            .public_base_url("http://127.0.0.1:3000")
            .build()
            .expect("ssr-only build");
        assert_eq!(services.public_base_url, "http://127.0.0.1:3000");
    }

    #[cfg(feature = "webauthn")]
    #[test]
    fn services_webauthn_rp_optional_and_require_sad() {
        #[cfg(feature = "email")]
        let email = lepton_smtp::EmailServiceBuilder::new()
            .noop()
            .build()
            .expect("noop email");
        #[cfg(feature = "phone")]
        let sms = lepton_sms::SmsServiceBuilder::new()
            .noop()
            .build()
            .expect("noop sms");

        #[allow(unused_mut)] // reassigned when email/phone features attach services
        let mut without_builder =
            LeptonAuthServicesBuilder::new().public_base_url("http://127.0.0.1:3000");
        #[cfg(feature = "email")]
        {
            without_builder = without_builder.email(email.clone());
        }
        #[cfg(feature = "phone")]
        {
            without_builder = without_builder.sms(sms.clone());
        }
        let without = without_builder.build().expect("build without rp");
        assert!(without.webauthn_rp.is_none());
        assert!(matches!(
            without.require_webauthn_rp(),
            Err(crate::devices::DeviceError::Config)
        ));

        let rp = WebauthnRpConfig {
            rp_id: "localhost".into(),
            rp_origin: "http://127.0.0.1:3000".into(),
            rp_name: "Lepton".into(),
        };
        #[allow(unused_mut)] // reassigned when email/phone features attach services
        let mut with_builder = LeptonAuthServicesBuilder::new()
            .public_base_url("http://127.0.0.1:3000")
            .webauthn_rp(rp.clone());
        #[cfg(feature = "email")]
        {
            with_builder = with_builder.email(email);
        }
        #[cfg(feature = "phone")]
        {
            with_builder = with_builder.sms(sms);
        }
        let with = with_builder.build().expect("build with rp");
        assert_eq!(with.require_webauthn_rp().expect("rp"), &rp);
    }

    #[cfg(feature = "email")]
    #[test]
    fn builder_requires_email_when_email_feature() {
        let err = LeptonAuthServicesBuilder::new().build();
        assert!(err.is_err());
    }

    #[cfg(feature = "phone")]
    #[test]
    fn builder_requires_sms_when_phone_feature() {
        let err = LeptonAuthServicesBuilder::new().public_base_url("http://127.0.0.1:3000");
        #[cfg(feature = "email")]
        let err = {
            let email = lepton_smtp::EmailServiceBuilder::new()
                .noop()
                .build()
                .expect("noop email");
            err.email(email).build()
        };
        #[cfg(not(feature = "email"))]
        let err = err.build();
        assert!(err.is_err());
    }

    #[cfg(all(feature = "email", feature = "phone"))]
    mod swap {
        use super::*;
        use crate::delivery_settings::{
            DeliveryError, EmailCandidate, EmailDriverChoice, SmsCandidate, SmsMode,
            WriteOnlySecret,
        };
        use lepton_smtp::{EmailDriver, EmailEnvelope};
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpListener;

        /// Minimal SMTP sink: accepts one message per connection and reports its text.
        async fn smtp_sink() -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let port = listener.local_addr().expect("addr").port();
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            tokio::spawn(async move {
                loop {
                    let Ok((sock, _)) = listener.accept().await else {
                        return;
                    };
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        let (r, mut w) = sock.into_split();
                        let mut r = BufReader::new(r);
                        let _ = w.write_all(b"220 sink ready\r\n").await;
                        let mut in_data = false;
                        let mut data = String::new();
                        let mut line = String::new();
                        loop {
                            line.clear();
                            if r.read_line(&mut line).await.unwrap_or(0) == 0 {
                                return;
                            }
                            if in_data {
                                if line == ".\r\n" {
                                    in_data = false;
                                    let _ = tx.send(std::mem::take(&mut data));
                                    let _ = w.write_all(b"250 queued\r\n").await;
                                } else {
                                    data.push_str(&line);
                                }
                                continue;
                            }
                            let cmd = line.trim().to_ascii_uppercase();
                            let reply: &[u8] = if cmd.starts_with("EHLO") {
                                b"250 sink\r\n"
                            } else if cmd.starts_with("DATA") {
                                in_data = true;
                                b"354 go\r\n"
                            } else if cmd.starts_with("QUIT") {
                                let _ = w.write_all(b"221 bye\r\n").await;
                                return;
                            } else {
                                b"250 ok\r\n"
                            };
                            let _ = w.write_all(reply).await;
                        }
                    });
                }
            });
            (port, rx)
        }

        fn envelope() -> EmailEnvelope {
            EmailEnvelope {
                to: "reader@example.test".into(),
                subject: "swap-probe".into(),
                text_body: "hello".into(),
                html_body: "<p>hello</p>".into(),
            }
        }

        fn smtp_candidate(port: u16, from: &str) -> EmailCandidate {
            EmailCandidate {
                driver: EmailDriverChoice::Smtp,
                smtp_host: "127.0.0.1".into(),
                smtp_port: port,
                smtp_tls: false,
                from_email: from.into(),
                test_recipient: "ops@example.test".into(),
                ..EmailCandidate::default()
            }
        }

        fn bundle() -> LeptonAuthServices {
            let email = lepton_smtp::EmailServiceBuilder::new()
                .noop()
                .build()
                .expect("noop email");
            let sms = lepton_sms::SmsServiceBuilder::new()
                .noop()
                .build()
                .expect("noop sms");
            LeptonAuthServicesBuilder::new()
                .email_swappable(email)
                .sms_swappable(sms)
                .build()
                .expect("bundle")
        }

        #[tokio::test]
        async fn smtp_settings_change_sends_next_email_through_new_settings_happy() {
            let (port_a, mut rx_a) = smtp_sink().await;
            let (port_b, mut rx_b) = smtp_sink().await;
            let services = bundle();
            assert_eq!(services.email.driver(), EmailDriver::Noop);

            services
                .apply_email_settings(&smtp_candidate(port_a, "first@example.test"), None, None)
                .expect("apply first");
            assert_eq!(services.email.driver(), EmailDriver::Smtp);
            services.email.send(&envelope()).await.expect("send first");
            let got = rx_a.recv().await.expect("first sink got mail");
            assert!(got.contains("first@example.test"), "{got}");

            // Change the settings: the next send goes to the new relay, same bundle.
            services
                .apply_email_settings(&smtp_candidate(port_b, "second@example.test"), None, None)
                .expect("apply second");
            services.email.send(&envelope()).await.expect("send second");
            let got = rx_b.recv().await.expect("second sink got mail");
            assert!(got.contains("second@example.test"), "{got}");
            assert!(rx_a.try_recv().is_err(), "old relay must not see the send");
        }

        #[tokio::test]
        async fn invalid_email_settings_keep_current_service_sad() {
            let services = bundle();
            let bad = EmailCandidate {
                driver: EmailDriverChoice::Smtp,
                ..EmailCandidate::default()
            };
            let err = services
                .apply_email_settings(&bad, None, None)
                .expect_err("invalid");
            assert!(matches!(err, DeliveryError::Invalid { .. }));
            assert_eq!(services.email.driver(), EmailDriver::Noop);

            // Username without a resolved password is refused, not sent unauthenticated.
            let mut no_pw = smtp_candidate(2525, "a@example.test");
            no_pw.smtp_username = "user".into();
            assert!(services.apply_email_settings(&no_pw, None, None).is_err());
            assert_eq!(services.email.driver(), EmailDriver::Noop);
        }

        #[test]
        fn fixed_adapter_bundle_is_not_swappable_sad() {
            let email = lepton_smtp::EmailServiceBuilder::new()
                .noop()
                .build()
                .expect("noop email");
            let sms = lepton_sms::SmsServiceBuilder::new()
                .noop()
                .build()
                .expect("noop sms");
            let fixed = LeptonAuthServicesBuilder::new()
                .email(email.clone())
                .sms(sms.clone())
                .build()
                .expect("fixed");
            assert!(matches!(
                fixed.replace_email(email),
                Err(LeptonAuthServicesError::NotSwappable { channel: "email" })
            ));
            assert!(matches!(
                fixed.replace_sms(sms),
                Err(LeptonAuthServicesError::NotSwappable { channel: "sms" })
            ));
        }

        #[test]
        fn sms_settings_change_swaps_driver() {
            let services = bundle();
            assert_eq!(services.sms.driver_name(), "noop");
            let candidate = SmsCandidate {
                mode: SmsMode::Verify,
                twilio_account_sid: "ACtest".into(),
                twilio_api_key_sid: "SKtest".into(),
                twilio_verify_service_sid: "VAtest".into(),
                test_recipient: "+15550100".into(),
                twilio_api_secret: Some(WriteOnlySecret::new("s3cret")),
                ..SmsCandidate::default()
            };
            // Missing resolved secret: refused, driver unchanged.
            assert!(services.apply_sms_settings(&candidate, None).is_err());
            assert_eq!(services.sms.driver_name(), "noop");
            services
                .apply_sms_settings(&candidate, Some("s3cret"))
                .expect("apply sms");
            assert_ne!(services.sms.driver_name(), "noop");
        }
    }
}
