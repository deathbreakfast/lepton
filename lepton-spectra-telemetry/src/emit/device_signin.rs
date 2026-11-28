//! Device sign-in counter.

use crate::helpers::LeptonDeviceSigninRecorder;

use super::common::{bound_error_class, AuthOutcome};

/// Device sign-in operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceSigninOperation {
    /// A device asked for a device code and user code.
    Start,
    /// The owner approved a device as one of their service users.
    Approve,
    /// The owner denied a device.
    Deny,
    /// The device collected its token.
    Issue,
    /// The owner moved a device to another service user.
    Move,
    /// The owner renamed a device.
    Rename,
    /// A device was signed out.
    SignOut,
}

impl DeviceSigninOperation {
    /// Spectra label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Approve => "approve",
            Self::Deny => "deny",
            Self::Issue => "issue",
            Self::Move => "move",
            Self::Rename => "rename",
            Self::SignOut => "sign_out",
        }
    }
}

/// Best-effort bump of `lepton_device_signin{operation,outcome,error_class}`.
///
/// Labels carry no device or user code, device name, address, service user, or user id.
pub fn record_device_signin(
    operation: DeviceSigninOperation,
    outcome: AuthOutcome,
    error_class: &'static str,
) {
    let error_class = bound_error_class(error_class);
    LeptonDeviceSigninRecorder::record(
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
    fn device_signin_labels_are_enum_only_happy() {
        let ops = [
            DeviceSigninOperation::Start,
            DeviceSigninOperation::Approve,
            DeviceSigninOperation::Deny,
            DeviceSigninOperation::Issue,
            DeviceSigninOperation::Move,
            DeviceSigninOperation::Rename,
            DeviceSigninOperation::SignOut,
        ];
        let labels: Vec<_> = ops.iter().map(|o| o.as_str()).collect();
        assert_eq!(
            labels,
            ["start", "approve", "deny", "issue", "move", "rename", "sign_out"]
        );
        for class in [
            "locked",
            "paused",
            "quota",
            "scopes",
            "expired",
            "access_denied",
            "invalid_grant",
            "slow_down",
            "authorization_pending",
            "step_up",
            "store",
        ] {
            assert_eq!(
                bound_error_class(class),
                class,
                "{class} must be allowlisted"
            );
        }
        record_device_signin(DeviceSigninOperation::Approve, AuthOutcome::Success, "none");
    }

    #[test]
    fn device_signin_unknown_class_bounded_sad() {
        assert_eq!(bound_error_class("WDJB-MJHT"), "unknown");
        record_device_signin(
            DeviceSigninOperation::Start,
            AuthOutcome::Failure,
            "WDJB-MJHT",
        );
    }
}
