//! Server-side helpers that turn auth events into delivered emails via `lepton-smtp`.
//!
//! Requires the `email` Cargo feature and [`crate::services::provide_auth_services`] at
//! boot. Stock `ssr::send_verification_token_email` / `ssr::send_password_reset_token_email`
//! always build envelopes with `lepton-smtp` helpers. For custom subject/body, build an
//! `lepton_smtp::EmailEnvelope` and call `auth_services()?.email.send(&envelope)`.
//! Quiet helpers never log recipient addresses.
//!
//! The verification code is 6 digits from [`crate::token_helpers::issue_email_verification_token`].
//! Pass it as `token_id`. A user gets one live code at a time, five wrong entries lock it for
//! five minutes, and the resend actions wait 60 seconds between emails.
//!
//! Sends verification and password-reset mail through the injected email adapter.
//! SMTP transport config, Twilio adapters, and template engines configure elsewhere.
//!
//! # When to call
//!
//! | Task | API |
//! |------|-----|
//! | Stock verification code mail | `ssr::send_verification_token_email` |
//! | Stock password-reset link mail | `ssr::send_password_reset_token_email` |
//! | Public token URL from injected base | `ssr::build_public_token_link` |
//! | Custom subject/body | `auth_services` + `lepton_smtp::EmailEnvelope` |
//!
//! # Examples
//!
//! Stock send after provide (`ssr` + `email`):
//!
//! ```rust,ignore
//! use lepton_auth::email_delivery::ssr::send_verification_token_email;
//! use lepton_smtp::VerificationEmailFlow;
//!
//! // provide_auth_services(...) already ran at boot
//! let _receipt = send_verification_token_email(
//!     "user@example.test",
//!     Some("Alex Rivera"),
//!     "tok123",
//!     VerificationEmailFlow::Signup,
//! )
//! .await?;
//! ```
//!
//! Custom envelope via the injected adapter:
//!
//! ```rust,ignore
//! use lepton_auth::services::auth_services;
//! use lepton_smtp::EmailEnvelope;
//!
//! let services = auth_services()?;
//! let envelope = EmailEnvelope {
//!     to: "user@example.test".into(),
//!     subject: "Confirm your Unified Field account".into(),
//!     text_body: "Your code is tok123".into(),
//!     html_body: "<p>Your code is <code>tok123</code></p>".into(),
//! };
//! services.email.send(&envelope).await?;
//! ```
//!
//! # Further reading
//!
//! [`lepton_smtp`] crate-root envelopes. Runnable transport smoke:
//! `examples/auth_flows_noop_smtp` / `auth_flows_smtp_mailpit` (do not call these
//! stock `send_*` helpers).

/// Verification/reset email dispatch built on `lepton-smtp`.
#[cfg(all(feature = "ssr", feature = "email"))]
pub mod ssr {
    use lepton_smtp::{
        password_reset_email_envelope, verification_email_envelope_named, DeliveryReceipt,
        VerificationEmailFlow,
    };
    use leptos::prelude::ServerFnError;

    use crate::services::auth_services;

    fn opaque_delivery_err() -> ServerFnError {
        ServerFnError::new("reason_class=delivery: email delivery failed")
    }

    fn opaque_services_err() -> ServerFnError {
        ServerFnError::new("reason_class=services: auth services unavailable")
    }

    /// Build and send a verification-code email for the given `flow`.
    ///
    /// `token_id` is the 6-digit code to show the user. It is a secret, so the queued delivery
    /// intent gets a random id instead of the code.
    ///
    /// # Errors
    ///
    /// Opaque delivery / services errors (no recipient or transport detail).
    pub async fn send_verification_token_email(
        recipient_email: &str,
        recipient_name: Option<&str>,
        token_id: &str,
        flow: VerificationEmailFlow,
    ) -> Result<DeliveryReceipt, ServerFnError> {
        let envelope =
            verification_email_envelope_named(recipient_email, recipient_name, token_id, flow);
        #[cfg(feature = "boson-delivery")]
        {
            use crate::delivery::{enqueue_email, EmailDeliveryIntent};
            let intent_kind = match flow {
                VerificationEmailFlow::Signup => "signup_verify",
                VerificationEmailFlow::Resend => "resend",
                VerificationEmailFlow::ChangeEmail => "change_email",
            };
            enqueue_email(EmailDeliveryIntent {
                intent_kind: intent_kind.into(),
                intent_id: uuid::Uuid::new_v4().to_string(),
                envelope,
            })
            .await
            .map_err(|_| opaque_delivery_err())?;
            Ok(DeliveryReceipt {
                provider: "queued".into(),
                message_id: None,
            })
        }
        #[cfg(not(feature = "boson-delivery"))]
        {
            let services = auth_services().map_err(|_| opaque_services_err())?;
            services
                .email
                .send(&envelope)
                .await
                .map_err(|_| opaque_delivery_err())
        }
    }

    /// Build and send a password-reset-link email.
    ///
    /// # Errors
    ///
    /// Opaque delivery / services errors (no recipient or transport detail).
    pub async fn send_password_reset_token_email(
        recipient_email: &str,
        token_id: &str,
    ) -> Result<DeliveryReceipt, ServerFnError> {
        let services = auth_services().map_err(|_| opaque_services_err())?;
        let reset_link = crate::routes::build_public_token_url(
            &services.public_base_url,
            crate::paths::RESET_PASSWORD_CONFIRM,
            token_id,
        );
        let envelope = password_reset_email_envelope(recipient_email, &reset_link);
        #[cfg(feature = "boson-delivery")]
        {
            use crate::delivery::{enqueue_email, EmailDeliveryIntent};
            enqueue_email(EmailDeliveryIntent {
                intent_kind: "password_reset".into(),
                intent_id: token_id.into(),
                envelope,
            })
            .await
            .map_err(|_| opaque_delivery_err())?;
            Ok(DeliveryReceipt {
                provider: "queued".into(),
                message_id: None,
            })
        }
        #[cfg(not(feature = "boson-delivery"))]
        {
            services
                .email
                .send(&envelope)
                .await
                .map_err(|_| opaque_delivery_err())
        }
    }

    /// Build a public, token-bearing URL for `path` from injected [`crate::services::LeptonAuthServices`].
    ///
    /// Tokens are placed in the URL fragment so they are not sent to the server or
    /// exposed via Referer on same-origin links.
    ///
    /// # Errors
    ///
    /// Opaque services error when [`crate::services::auth_services`] returns
    /// [`crate::services::LeptonAuthServicesError::NotInContext`].
    pub fn build_public_token_link(path: &str, token_id: &str) -> Result<String, ServerFnError> {
        let services = auth_services().map_err(|_| opaque_services_err())?;
        Ok(crate::routes::build_public_token_url(
            &services.public_base_url,
            path,
            token_id,
        ))
    }

    /// Send a verification email; log delivery failures without recipient or transport detail.
    pub async fn send_verification_token_email_quiet(
        recipient_email: &str,
        recipient_name: Option<&str>,
        token_id: &str,
        flow: VerificationEmailFlow,
    ) {
        if let Err(_e) =
            send_verification_token_email(recipient_email, recipient_name, token_id, flow).await
        {
            tracing::warn!(
                reason_class = "delivery",
                "email verification delivery failed (recipient omitted)"
            );
        }
    }

    /// Quiet password-reset send: always swallows delivery errors (anti-enumeration).
    pub async fn send_password_reset_token_email_quiet(recipient_email: &str, token_id: &str) {
        if let Err(_e) = send_password_reset_token_email(recipient_email, token_id).await {
            tracing::warn!(
                reason_class = "delivery",
                "password reset delivery failed (recipient omitted)"
            );
        }
    }
}

#[cfg(all(test, feature = "ssr", feature = "email"))]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::sync::Arc;

    use lepton_smtp::{EmailServiceBuilder, VerificationEmailFlow};
    use leptos::prelude::Owner;

    use crate::services::{
        auth_services, provide_auth_services, LeptonAuthServices, LeptonAuthServicesBuilder,
        LeptonAuthServicesError,
    };

    fn provide_noop_services(base: &str) -> Arc<LeptonAuthServices> {
        let email = EmailServiceBuilder::new()
            .noop()
            .build()
            .expect("noop email");
        let mut builder = LeptonAuthServicesBuilder::new()
            .email(email)
            .public_base_url(base);
        #[cfg(feature = "phone")]
        {
            let sms = lepton_sms::SmsServiceBuilder::new()
                .noop()
                .build()
                .expect("noop sms");
            builder = builder.sms(sms);
        }
        let services = Arc::new(builder.build().expect("services"));
        provide_auth_services(Arc::clone(&services));
        services
    }

    #[cfg(not(feature = "boson-delivery"))]
    #[tokio::test]
    async fn auth_services_send_uses_injected_email_happy_path() {
        let owner = Owner::new();
        owner.set();
        let services = provide_noop_services("https://app.example.test");
        let receipt = super::ssr::send_verification_token_email(
            "user@example.test",
            Some("Alex Rivera"),
            "tok123",
            VerificationEmailFlow::Signup,
        )
        .await
        .expect("send");
        assert_eq!(receipt.provider, "noop");
        assert_eq!(services.email.driver(), lepton_smtp::EmailDriver::Noop);
    }

    #[cfg(feature = "boson-delivery")]
    #[tokio::test]
    async fn auth_services_enqueue_without_boson_sad() {
        let owner = Owner::new();
        owner.set();
        let _ = provide_noop_services("https://app.example.test");
        let err = super::ssr::send_verification_token_email(
            "user@example.test",
            Some("Alex Rivera"),
            "tok123",
            VerificationEmailFlow::Signup,
        )
        .await
        .expect_err("enqueue needs boson");
        assert!(err.to_string().contains("reason_class=delivery"));
    }

    #[test]
    fn build_public_token_link_uses_services_base_url_happy_path() {
        let owner = Owner::new();
        owner.set();
        let _ = provide_noop_services("https://links.example.test");
        let link = super::ssr::build_public_token_link("/user/account", "abc").expect("link");
        assert!(link.starts_with("https://links.example.test/user/account#token="));
        assert!(link.contains("abc"));
    }

    #[test]
    fn auth_services_missing_context_sad() {
        let owner = Owner::new();
        owner.set();
        assert!(matches!(
            auth_services(),
            Err(LeptonAuthServicesError::NotInContext)
        ));
    }

    #[tokio::test]
    async fn quiet_reset_delivery_fail_client_ok_no_recipient() {
        let owner = Owner::new();
        owner.set();
        // No services provided → quiet path must not panic / must not require recipient logging.
        super::ssr::send_password_reset_token_email_quiet("user@example.test", "tok").await;
    }
}
