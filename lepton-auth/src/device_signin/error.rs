//! Why a device sign-in call was refused.

use crate::service_users::ServiceUserError;

/// Errors from looking up, approving, denying, renaming, moving or signing out a device.
///
/// Messages start with `reason_class=<class>` and never echo a code, handle, device name or
/// address. The approval and device pages pick their message by
/// [`reason_class`](Self::reason_class).
#[derive(Debug, thiserror::Error)]
pub enum DeviceSigninError {
    /// The caller is not a signed-in user.
    #[error("reason_class=actor: only a signed-in user can approve or manage devices")]
    NotAUser,
    /// No open request has that user code (unknown, expired or already decided), or the device
    /// or service user is unknown to the caller.
    #[error("reason_class=not_found: no such device request or device")]
    NotFound,
    /// Too many wrong user codes; the caller must wait before trying again.
    #[error("reason_class=locked: too many wrong codes, try again in a few minutes")]
    Locked,
    /// The service user or device belongs to someone else. Manage-any users get this too: only
    /// the owner signs a device in as a service user.
    #[error("reason_class=forbidden: not your service user or device")]
    Forbidden,
    /// The service user is paused; resume it first.
    #[error("reason_class=paused: the service user is paused")]
    Paused,
    /// The service user already has as many tokens (and devices waiting for one) as allowed.
    #[error("reason_class=quota: the service user has {limit} tokens already")]
    QuotaReached {
        /// The limit, [`MAX_TOKENS_PER_SERVICE_USER`](crate::service_users::MAX_TOKENS_PER_SERVICE_USER).
        limit: usize,
    },
    /// No API scope ticked, or one the host doesn't offer.
    #[error("reason_class=scopes: pick at least one offered API")]
    InvalidScopes,
    /// A field failed validation, such as an empty device name.
    #[error("reason_class=profile: invalid {field}")]
    InvalidInput {
        /// The field name.
        field: &'static str,
    },
    /// The host registered no API scopes.
    #[error("reason_class=not_configured: no API scopes registered")]
    ScopesNotRegistered,
    /// Approving or moving needs a recent step-up and there is none. `reason_class` is the
    /// step-up error's own class.
    #[error("reason_class=step_up: step-up needed ({reason_class})")]
    StepUp {
        /// The step-up error's class, such as `step_up_required`.
        reason_class: &'static str,
    },
    /// Creating the new service user for the device failed; carries why (a taken handle comes
    /// with a free suggestion).
    #[error("{0}")]
    ServiceUser(ServiceUserError),
    /// A storage failure.
    #[error("reason_class=store: device sign-in store operation failed")]
    Store,
}

impl DeviceSigninError {
    /// Stable, loggable cause class.
    #[must_use]
    pub const fn reason_class(&self) -> &'static str {
        match self {
            Self::NotAUser => "actor",
            Self::NotFound => "not_found",
            Self::Locked => "locked",
            Self::Forbidden => "forbidden",
            Self::Paused => "paused",
            Self::QuotaReached { .. } => "quota",
            Self::InvalidScopes => "scopes",
            Self::InvalidInput { .. } => "profile",
            Self::ScopesNotRegistered => "not_configured",
            Self::StepUp { .. } => "step_up",
            Self::ServiceUser(e) => e.reason_class(),
            Self::Store => "store",
        }
    }
}

impl From<ServiceUserError> for DeviceSigninError {
    fn from(e: ServiceUserError) -> Self {
        match e {
            ServiceUserError::NotAUser => Self::NotAUser,
            ServiceUserError::NotFound => Self::NotFound,
            ServiceUserError::Forbidden => Self::Forbidden,
            ServiceUserError::QuotaReached { limit } => Self::QuotaReached { limit },
            ServiceUserError::ScopesNotRegistered => Self::ScopesNotRegistered,
            ServiceUserError::Store => Self::Store,
            other => Self::ServiceUser(other),
        }
    }
}

#[cfg(feature = "totp")]
impl DeviceSigninError {
    /// Map a failed step-up check like [`ServiceUserError`] does.
    pub(crate) const fn from_step_up(e: &crate::step_up::StepUpError) -> Self {
        use crate::step_up::StepUpError;
        match e {
            StepUpError::AuthRequired => Self::NotAUser,
            StepUpError::Store => Self::Store,
            other => Self::StepUp {
                reason_class: other.reason_class(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_classes_happy() {
        assert_eq!(DeviceSigninError::Locked.reason_class(), "locked");
        assert_eq!(DeviceSigninError::Paused.reason_class(), "paused");
        assert_eq!(
            DeviceSigninError::QuotaReached { limit: 10 }.reason_class(),
            "quota"
        );
        assert_eq!(
            DeviceSigninError::from(ServiceUserError::HandleTaken { suggestion: None })
                .reason_class(),
            "handle_taken"
        );
        assert!(matches!(
            DeviceSigninError::from(ServiceUserError::Forbidden),
            DeviceSigninError::Forbidden
        ));
    }

    #[test]
    fn messages_lead_with_reason_class_happy() {
        for e in [
            DeviceSigninError::NotFound,
            DeviceSigninError::Locked,
            DeviceSigninError::Forbidden,
            DeviceSigninError::Paused,
            DeviceSigninError::InvalidScopes,
        ] {
            assert!(
                e.to_string()
                    .starts_with(&format!("reason_class={}", e.reason_class())),
                "{e}"
            );
        }
    }
}
