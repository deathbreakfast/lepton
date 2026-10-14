//! Contract between the settings page (server functions) and the host.
//!
//! The page lives in an L2 product and must not depend on the secret vault
//! (L3). It calls this trait; the host provides the implementation through
//! Leptos context, the same decoupling `uf-product` uses for permissions.
//!
//! Every method receives the **request** Valence, so reads and writes run as
//! the signed-in operator and are subject to Valence privacy policies. An
//! implementation must not rebind to System inside these calls.

use async_trait::async_trait;
use valence::Valence;

use super::settings::{
    DeliveryError, DeliverySettingsView, EmailCandidate, OAuthCandidate, SmsCandidate,
};

/// Host-provided operations behind the "Sign-in and delivery" page.
#[async_trait]
pub trait DeliverySettingsBackend: Send + Sync {
    /// Current settings, with secrets reduced to set/unset and last rotated.
    ///
    /// # Errors
    ///
    /// [`DeliveryError::PermissionDenied`] when the actor may not read the settings row.
    async fn view(&self, v: &Valence) -> Result<DeliverySettingsView, DeliveryError>;

    /// Send one test email with the candidate values. Persists nothing.
    ///
    /// # Errors
    ///
    /// [`DeliveryError::Invalid`] for bad input, [`DeliveryError::TestSendFailed`]
    /// when the provider rejects the message.
    async fn test_email(
        &self,
        v: &Valence,
        candidate: &EmailCandidate,
    ) -> Result<(), DeliveryError>;

    /// Send one test text message with the candidate values. Persists nothing.
    ///
    /// # Errors
    ///
    /// Same classes as [`test_email`](Self::test_email).
    async fn test_sms(&self, v: &Valence, candidate: &SmsCandidate) -> Result<(), DeliveryError>;

    /// Test then save email settings. A failed test persists nothing.
    ///
    /// # Errors
    ///
    /// [`DeliveryError::TestSendFailed`] leaves settings and secrets untouched.
    /// [`DeliveryError::SaveNotApplied`] means secrets changed but the row did not.
    async fn save_email(&self, v: &Valence, candidate: EmailCandidate)
        -> Result<(), DeliveryError>;

    /// Test then save text-message settings.
    ///
    /// # Errors
    ///
    /// Same classes as [`save_email`](Self::save_email).
    async fn save_sms(&self, v: &Valence, candidate: SmsCandidate) -> Result<(), DeliveryError>;

    /// Save OAuth client ids and any replaced client secrets.
    ///
    /// # Errors
    ///
    /// [`DeliveryError::Invalid`], [`DeliveryError::SecretStore`], or
    /// [`DeliveryError::SaveNotApplied`].
    async fn save_oauth(&self, v: &Valence, candidate: OAuthCandidate)
        -> Result<(), DeliveryError>;

    /// Create the next TOTP seal key version and make it current. Older versions
    /// stay readable so existing authenticators keep working.
    ///
    /// # Errors
    ///
    /// [`DeliveryError::SecretStore`] or [`DeliveryError::SaveNotApplied`].
    async fn rotate_totp_key(&self, v: &Valence) -> Result<(), DeliveryError>;
}
