//! Bot account lifecycle counter.

use crate::helpers::LeptonBotRecorder;

use super::common::{bound_error_class, AuthOutcome};

/// Bot lifecycle operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BotOperation {
    /// Create a bot.
    Create,
    /// Edit display name or description.
    Update,
    /// Suspend an active bot.
    Suspend,
    /// Resume a suspended bot.
    Resume,
    /// Delete a bot.
    Delete,
}

impl BotOperation {
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

/// Best-effort bump of `lepton_bot{operation,outcome,error_class}`.
///
/// Labels carry no bot id, handle, or user id.
pub fn record_bot(operation: BotOperation, outcome: AuthOutcome, error_class: &'static str) {
    let error_class = bound_error_class(error_class);
    LeptonBotRecorder::record(
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
    fn bot_metric_labels_are_enum_only_happy() {
        let ops = [
            BotOperation::Create,
            BotOperation::Update,
            BotOperation::Suspend,
            BotOperation::Resume,
            BotOperation::Delete,
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
        record_bot(BotOperation::Create, AuthOutcome::Success, "none");
    }

    #[test]
    fn bot_metric_unknown_class_bounded_sad() {
        assert_eq!(bound_error_class("spectra-bot"), "unknown");
        record_bot(BotOperation::Create, AuthOutcome::Failure, "spectra-bot");
    }
}
