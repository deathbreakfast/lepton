//! OAuth begin/complete counter.

use crate::helpers::LeptonOauthRecorder;

use super::common::{bound_error_class, AuthOutcome};

/// OAuth provider label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OAuthProviderLabel {
    /// Google.
    Google,
    /// GitHub.
    Github,
    /// Microsoft.
    Microsoft,
    /// Mock provider.
    Mock,
    /// Unknown / unbounded.
    Unknown,
}

impl OAuthProviderLabel {
    /// Spectra label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::Github => "github",
            Self::Microsoft => "microsoft",
            Self::Mock => "mock",
            Self::Unknown => "unknown",
        }
    }
}

/// OAuth intent label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OAuthIntentLabel {
    /// Login.
    Login,
    /// Signup.
    Signup,
    /// Link identity.
    Link,
}

impl OAuthIntentLabel {
    /// Spectra label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Signup => "signup",
            Self::Link => "link",
        }
    }
}

/// OAuth stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OAuthStage {
    /// Begin authorize.
    Begin,
    /// Complete callback.
    Complete,
}

impl OAuthStage {
    /// Spectra label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Begin => "begin",
            Self::Complete => "complete",
        }
    }
}

const OAUTH_PROVIDERS: &[&str] = &["google", "github", "microsoft", "mock"];

/// Map a provider string to an allowlisted label (or `unknown`).
#[must_use]
pub fn bound_oauth_provider(raw: &str) -> &'static str {
    let trimmed = raw.trim();
    OAUTH_PROVIDERS
        .iter()
        .copied()
        .find(|&p| p.eq_ignore_ascii_case(trimmed))
        .unwrap_or("unknown")
}

/// Best-effort bump of `lepton_oauth{provider,intent,stage,outcome,error_class}`.
pub fn record_oauth(
    provider: OAuthProviderLabel,
    intent: OAuthIntentLabel,
    stage: OAuthStage,
    outcome: AuthOutcome,
    error_class: &'static str,
) {
    let error_class = bound_error_class(error_class);
    LeptonOauthRecorder::record(
        1,
        serde_json::json!({
            "provider": provider.as_str(),
            "intent": intent.as_str(),
            "stage": stage.as_str(),
            "outcome": outcome.as_str(),
            "error_class": error_class,
        }),
    );
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn record_oauth_maps_labels_happy() {
        assert_eq!(bound_oauth_provider("Google"), "google");
        record_oauth(
            OAuthProviderLabel::Google,
            OAuthIntentLabel::Signup,
            OAuthStage::Complete,
            AuthOutcome::Success,
            "none",
        );
    }

    #[test]
    fn record_oauth_unknown_provider_bounded_sad() {
        assert_eq!(bound_oauth_provider("user@x.test"), "unknown");
        assert_eq!(bound_oauth_provider("custom"), "unknown");
        record_oauth(
            OAuthProviderLabel::Unknown,
            OAuthIntentLabel::Login,
            OAuthStage::Begin,
            AuthOutcome::Failure,
            "oauth_config",
        );
    }

    #[test]
    fn record_oauth_without_spectra_soft_happy() {
        record_oauth(
            OAuthProviderLabel::Mock,
            OAuthIntentLabel::Link,
            OAuthStage::Begin,
            AuthOutcome::NeedsLink,
            "none",
        );
    }
}
