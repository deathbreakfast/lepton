//! Delivery settings for hosts that keep email, SMS, OAuth and TOTP-seal
//! settings outside process env.
//!
//! - [`settings`]: serde types for the settings page. No field can hold a
//!   secret value; secrets travel only toward the server as
//!   [`WriteOnlySecret`].
//! - [`admin`]: the [`DeliverySettingsBackend`] contract the page calls
//!   (`ssr`).
//! - `SwappableEmail` / `SwappableSms` (`ssr`): adapters whose target can be
//!   replaced while the process runs. They implement the same traits as the
//!   adapters they wrap, so [`crate::services::LeptonAuthServices`] and every
//!   send path keep calling `services.email.send(..)` unchanged. A send already
//!   in flight finishes on the adapter it started with.

#[cfg(feature = "ssr")]
pub mod admin;
pub mod settings;
#[cfg(feature = "ssr")]
mod swap;

#[cfg(feature = "ssr")]
pub use admin::DeliverySettingsBackend;
pub use settings::{
    Channel, DeliveryError, DeliverySettingsView, EmailCandidate, EmailDriverChoice,
    EmailSettingsView, OAuthCandidate, OAuthProviderView, OAuthSettingsView, SecretStatus,
    SmsCandidate, SmsMode, SmsSettingsView, TestFailureClass, TotpKeyView, WriteOnlySecret,
};
#[cfg(all(feature = "ssr", feature = "email"))]
pub use swap::SwappableEmail;
#[cfg(all(feature = "ssr", feature = "phone"))]
pub use swap::SwappableSms;
