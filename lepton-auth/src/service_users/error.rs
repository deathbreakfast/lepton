//! Errors from service user lifecycle calls.

use lepton_host_adapter::generated::ServiceUserAccountStatus;
use lepton_identity::service_users::{
    ServiceUserGateError, ServiceUserHandle, ServiceUserHandleError,
};
use thiserror::Error;

/// Why a service user lifecycle call failed.
///
/// Messages start with `reason_class=<class>` and never echo the handle, name,
/// or description the caller sent. [`ServiceUserError::HandleTaken`] carries a handle
/// the service generated, not caller input.
#[derive(Debug, Error)]
pub enum ServiceUserError {
    /// The caller is not a signed-in user. Service users (registered or built-in), System, and
    /// anonymous callers cannot create or manage service users.
    #[error("reason_class=actor: only a signed-in user can manage service users")]
    NotAUser,
    /// The host's service user gate does not let this user create service users.
    #[error("reason_class=permission: not allowed to create service users")]
    CreateNotPermitted,
    /// No [`ServiceUserGate`](lepton_identity::service_users::ServiceUserGate) is installed,
    /// so nobody can create service users. A host configuration problem.
    #[error("reason_class=not_configured: no service user gate installed")]
    GateNotInstalled,
    /// The service user gate could not reach a decision.
    #[error("reason_class=gate: service user gate failed ({0})")]
    Gate(ServiceUserGateError),
    /// The handle breaks a handle rule.
    #[error("reason_class=handle: invalid handle ({})", .0.reason())]
    InvalidHandle(ServiceUserHandleError),
    /// The caller already owns the most service users allowed
    /// ([`MAX_SERVICE_USERS_PER_OWNER`](super::MAX_SERVICE_USERS_PER_OWNER)). Deleting one frees a slot.
    #[error("reason_class=quota: service user limit of {limit} reached")]
    QuotaReached {
        /// The per-owner limit.
        limit: usize,
    },
    /// Another service user already uses this handle (ignoring case and dashes).
    #[error("reason_class=handle_taken: handle already in use")]
    HandleTaken {
        /// A free alternative, when one was found.
        suggestion: Option<ServiceUserHandle>,
    },
    /// The display name or description is empty or too long.
    #[error("reason_class=profile: invalid {field}")]
    InvalidProfile {
        /// `display_name` or `description`.
        field: &'static str,
    },
    /// No such service user, or the caller may not see it. The two are deliberately
    /// indistinguishable.
    #[error("reason_class=not_found: service user not found")]
    NotFound,
    /// The service user is already in the requested state.
    #[error("reason_class=transition: service user is already {from}")]
    InvalidTransition {
        /// Current status.
        from: ServiceUserAccountStatus,
    },
    /// The caller can see the service user but may not change it.
    #[error("reason_class=forbidden: not allowed to change this service user")]
    Forbidden,
    /// Storage failed.
    #[error("reason_class=store: service user store operation failed")]
    Store,
}

impl ServiceUserError {
    /// Stable, loggable cause class.
    #[must_use]
    pub const fn reason_class(&self) -> &'static str {
        match self {
            Self::NotAUser => "actor",
            Self::CreateNotPermitted => "permission",
            Self::GateNotInstalled => "not_configured",
            Self::Gate(_) => "gate",
            Self::InvalidHandle(_) => "handle",
            Self::QuotaReached { .. } => "quota",
            Self::HandleTaken { .. } => "handle_taken",
            Self::InvalidProfile { .. } => "profile",
            Self::NotFound => "not_found",
            Self::InvalidTransition { .. } => "transition",
            Self::Forbidden => "forbidden",
            Self::Store => "store",
        }
    }
}

impl From<ServiceUserHandleError> for ServiceUserError {
    fn from(e: ServiceUserHandleError) -> Self {
        Self::InvalidHandle(e)
    }
}
