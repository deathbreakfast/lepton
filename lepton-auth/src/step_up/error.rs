//! Typed errors for step-up verify / require.

use thiserror::Error;

/// Failures from step-up verify or window require.
#[derive(Debug, Error)]
pub enum StepUpError {
    /// No authenticated session / user.
    #[error("reason_class=auth_required: authentication required")]
    AuthRequired,
    /// No enabled TOTP factor; send the user to Account Settings.
    #[error("reason_class=totp_enrollment_required: enroll totp in account settings")]
    TotpEnrollmentRequired,
    /// Presented code rejected or reused within the same time step.
    #[error("reason_class=step_up_invalid: invalid or reused totp code")]
    StepUpInvalid,
    /// Attempt budget exhausted; wait for lockout to expire.
    #[error("reason_class=step_up_rate_limited: too many totp attempts")]
    StepUpRateLimited,
    /// No unexpired window for the requested scope.
    #[error("reason_class=step_up_required: recent totp verification required")]
    StepUpRequired,
    /// Window aged out mid-flow.
    #[error("reason_class=step_up_expired: totp verification expired")]
    StepUpExpired,
    /// Session store or Valence persistence failure (opaque).
    #[error("reason_class=store: step-up store failed")]
    Store,
    /// Sealed secret / crypto failure (opaque).
    #[error("reason_class=totp_secret: totp secret error")]
    TotpSecret,
}

impl StepUpError {
    /// Stable reason class for ops / UI mapping.
    #[must_use]
    pub const fn reason_class(&self) -> &'static str {
        match self {
            Self::AuthRequired => "auth_required",
            Self::TotpEnrollmentRequired => "totp_enrollment_required",
            Self::StepUpInvalid => "step_up_invalid",
            Self::StepUpRateLimited => "step_up_rate_limited",
            Self::StepUpRequired => "step_up_required",
            Self::StepUpExpired => "step_up_expired",
            Self::Store => "store",
            Self::TotpSecret => "totp_secret",
        }
    }

    /// Map into a Leptos [`ServerFnError`](leptos::prelude::ServerFnError) with a
    /// stable leading token the UI can detect.
    #[must_use]
    pub fn to_server_fn_error(&self) -> leptos::prelude::ServerFnError {
        leptos::prelude::ServerFnError::new(format!("STEP_UP:{}: {self}", self.reason_class()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_fn_error_carries_stable_prefix() {
        let err = StepUpError::StepUpRequired.to_server_fn_error();
        let msg = err.to_string();
        assert!(
            msg.contains("STEP_UP:step_up_required:"),
            "expected STEP_UP prefix, got {msg}"
        );
    }

    #[test]
    fn expired_reason_class() {
        assert_eq!(StepUpError::StepUpExpired.reason_class(), "step_up_expired");
    }
}
