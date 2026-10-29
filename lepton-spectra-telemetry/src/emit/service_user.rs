//! Service user lifecycle counter.

use crate::helpers::LeptonServiceUserRecorder;

use super::common::{bound_error_class, AuthOutcome};

/// Service user lifecycle operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceUserOperation {
    /// Create a service user.
    Create,
    /// Edit display name or description.
    Update,
    /// Suspend an active service user.
    Suspend,
    /// Resume a suspended service user.
    Resume,
    /// Delete a service user.
    Delete,
}

impl ServiceUserOperation {
    /// Spectra label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Suspend => "suspend",
            Self::Resume => "resume",
            Self::Delete => "delete",
        }
    }
}

/// Best-effort bump of `lepton_service_user{operation,outcome,error_class}`.
///
/// Labels carry no service user id, handle, or user id.
pub fn record_service_user(
    operation: ServiceUserOperation,
    outcome: AuthOutcome,
    error_class: &'static str,
) {
    let error_class = bound_error_class(error_class);
    LeptonServiceUserRecorder::record(
        1,
        serde_json::json!({
            "operation": operation.as_str(),
            "outcome": outcome.as_str(),
            "error_class": error_class,
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_user_metric_labels_are_enum_only_happy() {
        let ops = [
            ServiceUserOperation::Create,
            ServiceUserOperation::Update,
            ServiceUserOperation::Suspend,
            ServiceUserOperation::Resume,
            ServiceUserOperation::Delete,
        ];
        let labels: Vec<_> = ops.iter().map(|o| o.as_str()).collect();
        assert_eq!(labels, ["create", "update", "suspend", "resume", "delete"]);
        for class in [
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
            "store",
        ] {
            assert_eq!(
                bound_error_class(class),
                class,
                "{class} must be allowlisted"
            );
        }
        record_service_user(ServiceUserOperation::Create, AuthOutcome::Success, "none");
    }

    #[test]
    fn service_user_metric_unknown_class_bounded_sad() {
        assert_eq!(bound_error_class("spectra-agent"), "unknown");
        record_service_user(
            ServiceUserOperation::Create,
            AuthOutcome::Failure,
            "spectra-agent",
        );
    }
}
