//! Durable delivery metadata: Boson enqueue, attempt log, and process runtime.
//!
//! Requires Cargo features `ssr` + `boson-delivery` (and `email` / `phone` for the
//! matching channel). Sync [`crate::email_delivery`] remains available when
//! `boson-delivery` is off.
//!
//! Provides [`crate::delivery::DeliveryRuntime`],
//! [`crate::delivery::record_delivery_attempt`], enqueue façades, and Boson task handlers.
//! SMTP/SMS adapters, Spectra counters, and delivery status UI integrate at the host.
//!
//! # Concern → API
//!
//! | Concern | API |
//! |---------|-----|
//! | Install adapters for workers | [`DeliveryRuntime::install`](crate::delivery::DeliveryRuntime::install) |
//! | Persist attempt + provider id | [`record_delivery_attempt`] |
//! | Enqueue email / SMS | [`enqueue_email`] / [`enqueue_sms`] |
//! | Task handlers | [`crate::delivery::tasks`] |
//!
//! # Examples
//!
//! Host boot (install runtime alongside [`crate::services::provide_auth_services`]):
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use lepton_auth::delivery::DeliveryRuntime;
//! use lepton_auth::services::{provide_auth_services, LeptonAuthServicesBuilder};
//! use lepton_smtp::EmailServiceBuilder;
//!
//! let email = EmailServiceBuilder::new().noop()?;
//! DeliveryRuntime::install(DeliveryRuntime::builder().email(email.clone()).build())?;
//! provide_auth_services(
//!     LeptonAuthServicesBuilder::new()
//!         .public_base_url("http://127.0.0.1:3000")
//!         .email(email)
//!         .build()?,
//! );
//! ```
//!
//! Enqueue a verification email:
//!
//! ```rust,ignore
//! use lepton_auth::delivery::{enqueue_email, EmailDeliveryIntent};
//! use lepton_smtp::{verification_email_envelope_named, VerificationEmailFlow};
//!
//! let envelope = verification_email_envelope_named(
//!     "user@example.test",
//!     Some("Alex"),
//!     "tok123",
//!     VerificationEmailFlow::Signup,
//! );
//! enqueue_email(EmailDeliveryIntent {
//!     intent_kind: "signup_verify",
//!     intent_id: "tok123",
//!     envelope,
//! })
//! .await?;
//! ```

mod attempt;
mod enqueue;
mod runtime;

#[cfg(feature = "boson-delivery")]
pub mod tasks;

pub use attempt::{record_delivery_attempt, DeliveryAttemptInput, DeliveryAttemptWriteError};
pub use enqueue::EnqueueDeliveryError;
#[cfg(feature = "email")]
pub use enqueue::{enqueue_email, EmailDeliveryIntent};
#[cfg(feature = "phone")]
pub use enqueue::{enqueue_sms, SmsDeliveryIntent};
pub use runtime::{DeliveryRuntime, DeliveryRuntimeBuilder, DeliveryRuntimeError};
