//! Errors from bot lifecycle calls.

use lepton_host_adapter::generated::BotStatus;
use lepton_identity::bots::{BotGateError, BotHandle, BotHandleError};
use thiserror::Error;

/// Why a bot lifecycle call failed.
///
/// Messages start with `reason_class=<class>` and never echo the handle, name,
/// or description the caller sent. [`BotError::HandleTaken`] carries a handle
/// the service generated, not caller input.
#[derive(Debug, Error)]
pub enum BotError {
    /// The caller is not a signed-in user. Bots, service users, System, and
    /// anonymous callers cannot create or manage bots.
    #[error("reason_class=actor: only a signed-in user can manage bots")]
    NotAUser,
    /// The host's bot gate does not let this user create bots.
    #[error("reason_class=permission: not allowed to create bots")]
    CreateNotPermitted,
    /// No [`BotGate`](lepton_identity::bots::BotGate) is installed, so nobody can
    /// create bots. A host configuration problem.
    #[error("reason_class=not_configured: no bot gate installed")]
    GateNotInstalled,
    /// The bot gate could not reach a decision.
    #[error("reason_class=gate: bot gate failed ({0})")]
    Gate(BotGateError),
    /// The handle breaks a handle rule.
    #[error("reason_class=handle: invalid handle ({})", .0.reason())]
    InvalidHandle(BotHandleError),
    /// Another bot already uses this handle (ignoring case and dashes).
    #[error("reason_class=handle_taken: handle already in use")]
    HandleTaken {
        /// A free alternative, when one was found.
        suggestion: Option<BotHandle>,
    },
    /// The display name or description is empty or too long.
    #[error("reason_class=profile: invalid {field}")]
    InvalidProfile {
        /// `display_name` or `description`.
        field: &'static str,
    },
    /// No such bot, or the caller may not see it. The two are deliberately
    /// indistinguishable.
    #[error("reason_class=not_found: bot not found")]
    NotFound,
    /// The bot is already in the requested state.
    #[error("reason_class=transition: bot is already {from}")]
    InvalidTransition {
        /// Current status.
        from: BotStatus,
    },
    /// The caller can see the bot but may not change it.
    #[error("reason_class=forbidden: not allowed to change this bot")]
    Forbidden,
    /// Storage failed.
    #[error("reason_class=store: bot store operation failed")]
    Store,
}

impl BotError {
    /// Stable, loggable cause class.
    #[must_use]
    pub const fn reason_class(&self) -> &'static str {
        match self {
            Self::NotAUser => "actor",
            Self::CreateNotPermitted => "permission",
            Self::GateNotInstalled => "not_configured",
            Self::Gate(_) => "gate",
            Self::InvalidHandle(_) => "handle",
            Self::HandleTaken { .. } => "handle_taken",
            Self::InvalidProfile { .. } => "profile",
            Self::NotFound => "not_found",
            Self::InvalidTransition { .. } => "transition",
            Self::Forbidden => "forbidden",
            Self::Store => "store",
        }
    }
}

impl From<BotHandleError> for BotError {
    fn from(e: BotHandleError) -> Self {
        Self::InvalidHandle(e)
    }
}
