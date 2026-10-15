//! Host port deciding who may create bots and who may manage any bot.

use std::fmt;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use valence::Valence;

/// Decides bot permissions for the actor on a request [`Valence`].
///
/// Lepton cannot depend on a permission system (Gauge depends on Lepton), so the
/// host supplies this decision once at boot with [`install_bot_gate`]. Lepton's
/// privacy rules on the `bot` table call it, so the decision holds on every path
/// that writes bots: server functions, Boson tasks, and Chronon jobs alike.
///
/// Implementations receive the caller's own Valence. They must not rebind it to
/// `Actor::System`, and they must read any backing tables with raw backend reads
/// rather than typed models, because they run inside privacy evaluation.
/// Only `Actor::User` callers reach the gate; bots, service users, System, and
/// anonymous actors are refused before it is consulted.
#[async_trait]
pub trait BotGate: Send + Sync + 'static {
    /// May the actor on `valence` create a bot it will own?
    ///
    /// # Errors
    ///
    /// [`BotGateError`] when the decision could not be made. Callers treat an
    /// error as a refusal.
    async fn may_create_bot(&self, valence: &Valence) -> Result<bool, BotGateError>;

    /// May the actor on `valence` read, edit, suspend, and delete any bot,
    /// whoever owns it? Intended for super users.
    ///
    /// # Errors
    ///
    /// [`BotGateError`] when the decision could not be made. Callers treat an
    /// error as a refusal.
    async fn may_manage_any_bot(&self, valence: &Valence) -> Result<bool, BotGateError>;
}

/// A [`BotGate`] could not reach a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BotGateError {
    /// Stable, loggable cause class (for example `store`).
    pub reason_class: &'static str,
}

impl fmt::Display for BotGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "reason_class=gate: {}", self.reason_class)
    }
}

impl std::error::Error for BotGateError {}

/// [`install_bot_gate`] was called after a gate was already installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BotGateAlreadyInstalled;

impl fmt::Display for BotGateAlreadyInstalled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("reason_class=gate: a bot gate is already installed")
    }
}

impl std::error::Error for BotGateAlreadyInstalled {}

static GATE: OnceLock<Arc<dyn BotGate>> = OnceLock::new();

/// Install the process-wide [`BotGate`]. Call once at host boot, before
/// serving requests.
///
/// Until a gate is installed, nobody can create bots and nobody can manage
/// bots they do not own.
///
/// # Errors
///
/// [`BotGateAlreadyInstalled`] on a second call; the first gate stays in place.
pub fn install_bot_gate(gate: Arc<dyn BotGate>) -> Result<(), BotGateAlreadyInstalled> {
    GATE.set(gate).map_err(|_| BotGateAlreadyInstalled)
}

/// The installed gate, if any.
#[must_use]
pub fn installed_bot_gate() -> Option<Arc<dyn BotGate>> {
    GATE.get().cloned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    struct Fixed(bool);

    #[async_trait]
    impl BotGate for Fixed {
        async fn may_create_bot(&self, _v: &Valence) -> Result<bool, BotGateError> {
            Ok(self.0)
        }
        async fn may_manage_any_bot(&self, _v: &Valence) -> Result<bool, BotGateError> {
            Ok(self.0)
        }
    }

    // The only test in this binary that touches the global gate.
    #[test]
    fn install_bot_gate_twice_sad() {
        let first: Arc<dyn BotGate> = Arc::new(Fixed(false));
        install_bot_gate(Arc::clone(&first)).expect("first install");
        assert_eq!(
            install_bot_gate(Arc::new(Fixed(true))),
            Err(BotGateAlreadyInstalled)
        );
        let installed = installed_bot_gate().expect("installed");
        assert!(Arc::ptr_eq(&installed, &first), "first gate stays in place");
    }
}
