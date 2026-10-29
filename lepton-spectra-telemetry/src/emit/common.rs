//! Shared label enums and allowlists for auth Spectra emit.
//!
//! Helpers accept enums / allowlisted `&'static str` tokens only. Free-form strings
//! (including `Display` / `ServerFnError` text) must never be passed as label values.

/// Terminal auth outcome for funnel counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthOutcome {
    /// Flow completed successfully.
    Success,
    /// Flow failed.
    Failure,
    /// Password accepted; MFA still required.
    NeedsMfa,
    /// OAuth identity needs an existing-account link.
    NeedsLink,
}

impl AuthOutcome {
    /// Spectra label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::NeedsMfa => "needs_mfa",
            Self::NeedsLink => "needs_link",
        }
    }
}

/// MFA / session factor label on sign-in stages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthFactor {
    /// No factor (password stage or N/A).
    None,
    /// TOTP.
    Totp,
    /// `WebAuthn` passkey.
    Webauthn,
    /// Trusted-browser cookie skip.
    TrustedBrowser,
}

impl AuthFactor {
    /// Spectra label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Totp => "totp",
            Self::Webauthn => "webauthn",
            Self::TrustedBrowser => "trusted_browser",
        }
    }
}

/// Auth failure event `flow` dimension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthFailureFlow {
    /// Signup.
    Signup,
    /// Sign-in / session MFA.
    Signin,
    /// OAuth.
    Oauth,
    /// Verify (email/phone/TOTP challenge).
    Verify,
    /// Password reset.
    PasswordReset,
    /// TOTP enroll/disable.
    Totp,
    /// Devices.
    Device,
    /// Contacts.
    Contact,
    /// Account lifecycle.
    Account,
    /// Identity delete.
    IdentityDelete,
    /// Step-up.
    StepUp,
}

impl AuthFailureFlow {
    /// Spectra field value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Signup => "signup",
            Self::Signin => "signin",
            Self::Oauth => "oauth",
            Self::Verify => "verify",
            Self::PasswordReset => "password_reset",
            Self::Totp => "totp",
            Self::Device => "device",
            Self::Contact => "contact",
            Self::Account => "account",
            Self::IdentityDelete => "identity_delete",
            Self::StepUp => "step_up",
        }
    }
}

/// Closed allowlist of `error_class` / `reason_class` tokens used by Lepton auth.
///
/// Unknown inputs map to `unknown`. Never pass free-form error text here.
const ERROR_CLASSES: &[&str] = &[
    "none",
    "unknown",
    "validation",
    "email_exists",
    "feature",
    "store",
    "delivery",
    "account",
    "account_primary",
    "address_taken",
    "auth",
    "ceremony_invalid",
    "config",
    "confirm_blocked",
    "confirm_phrase",
    "contact",
    "device",
    "device_binding",
    "device_mismatch",
    "device_pending",
    "device_revoked",
    "expired",
    "factor",
    "invalid",
    "invalid_credentials",
    "last_membership",
    "link",
    "login",
    "membership",
    "mismatch",
    "missing_email",
    "missing_sms",
    "not_member",
    "not_owner",
    "oauth_account_taken",
    "oauth_config",
    "oauth_provider",
    "oauth_signup_email_collision",
    "oauth_state",
    "pending_expired",
    "pending_missing",
    "pending_stale",
    "restrict",
    "restrict_primary",
    "runtime",
    "services",
    "session",
    "sole_member",
    "status",
    "token",
    "totp_already_enabled",
    "totp_required",
    "totp_secret",
    "totp_unavailable",
    "unsupported_kind",
    "unverified_contact",
    "used",
    "user",
    "webauthn_browser",
    "webauthn_verify",
    // Service user lifecycle (`lepton_auth::service_users::ServiceUserError::reason_class`).
    "actor",
    "permission",
    "not_configured",
    "gate",
    "handle",
    "handle_taken",
    "profile",
    "not_found",
    "transition",
    "forbidden",
];

/// Map an `error_class` / `reason_class` token to an allowlisted label (or `unknown`).
#[must_use]
pub fn bound_error_class(raw: &str) -> &'static str {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return "unknown";
    }
    ERROR_CLASSES
        .iter()
        .copied()
        .find(|&c| c.eq_ignore_ascii_case(trimmed))
        .unwrap_or("unknown")
}

const OPTIONAL_PROVIDERS: &[&str] = &["google", "github", "mock", "none"];
const OPTIONAL_CHANNELS: &[&str] = &["email", "phone", "totp", "none"];

/// Bound optional provider label (`none` when absent / unknown).
#[must_use]
pub fn bound_optional_provider(raw: Option<&str>) -> &'static str {
    match raw {
        None | Some("") => "none",
        Some(v) => {
            let trimmed = v.trim();
            OPTIONAL_PROVIDERS
                .iter()
                .copied()
                .find(|&p| p.eq_ignore_ascii_case(trimmed))
                .unwrap_or("unknown")
        }
    }
}

/// Bound optional channel label (`none` when absent / unknown).
#[must_use]
pub fn bound_optional_channel(raw: Option<&str>) -> &'static str {
    match raw {
        None | Some("") => "none",
        Some(v) => {
            let trimmed = v.trim();
            OPTIONAL_CHANNELS
                .iter()
                .copied()
                .find(|&c| c.eq_ignore_ascii_case(trimmed))
                .unwrap_or("unknown")
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn bound_error_class_maps_known_happy() {
        assert_eq!(bound_error_class("none"), "none");
        assert_eq!(bound_error_class("validation"), "validation");
        assert_eq!(
            bound_error_class("INVALID_CREDENTIALS"),
            "invalid_credentials"
        );
        assert_eq!(
            bound_error_class("oauth_signup_email_collision"),
            "oauth_signup_email_collision"
        );
    }

    #[test]
    fn bound_error_class_unknown_and_pii_shapes_sad() {
        assert_eq!(bound_error_class("user@example.com"), "unknown");
        assert_eq!(bound_error_class("+15551234567"), "unknown");
        assert_eq!(bound_error_class("password=secret"), "unknown");
        assert_eq!(bound_error_class("123456"), "unknown");
        assert_eq!(bound_error_class(""), "unknown");
        assert_eq!(bound_error_class("Passwords do not match"), "unknown");
    }

    #[test]
    fn auth_outcome_and_factor_labels_happy() {
        assert_eq!(AuthOutcome::NeedsMfa.as_str(), "needs_mfa");
        assert_eq!(AuthFactor::TrustedBrowser.as_str(), "trusted_browser");
        assert_eq!(AuthFailureFlow::PasswordReset.as_str(), "password_reset");
    }
}
