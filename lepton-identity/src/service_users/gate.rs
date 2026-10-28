//! Host port deciding who may create service users and who may manage any service user.

use std::fmt;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use valence::Valence;

/// Decides service user permissions for the actor on a request [`Valence`].
///
/// Lepton cannot depend on a permission system (Gauge depends on Lepton), so the
/// host supplies this decision once at boot with [`install_service_user_gate`]. Lepton's
/// privacy rules on the `service_user_account` table call it, so the decision holds on every path
/// that writes service users: server functions, Boson tasks, and Chronon jobs alike.
///
/// Implementations receive the caller's own Valence. They must not rebind it to
/// `Actor::System`, and they must read any backing tables with raw backend reads
/// rather than typed models, because they run inside privacy evaluation.
/// Only `Actor::User` callers reach the gate; service users (registered or built-in), System, and
/// anonymous actors are refused before it is consulted.
#[async_trait]
pub trait ServiceUserGate: Send + Sync + 'static {
    /// May the actor on `valence` create a service user it will own?
    ///
    /// # Errors
    ///
    /// [`ServiceUserGateError`] when the decision could not be made. Callers treat an
    /// error as a refusal.
    async fn may_create_service_user(
        &self,
        valence: &Valence,
    ) -> Result<bool, ServiceUserGateError>;

    /// May the actor on `valence` read, edit, suspend, and delete any service user,
    /// whoever owns it? Intended for super users.
    ///
    /// # Errors
    ///
    /// [`ServiceUserGateError`] when the decision could not be made. Callers treat an
    /// error as a refusal.
    async fn may_manage_any_service_user(
        &self,
        valence: &Valence,
    ) -> Result<bool, ServiceUserGateError>;
}

/// A [`ServiceUserGate`] could not reach a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceUserGateError {
    /// Stable, loggable cause class (for example `store`).
    pub reason_class: &'static str,
}

impl fmt::Display for ServiceUserGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "reason_class=gate: {}", self.reason_class)
    }
}

impl std::error::Error for ServiceUserGateError {}

/// [`install_service_user_gate`] was called after a gate was already installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceUserGateAlreadyInstalled;

impl fmt::Display for ServiceUserGateAlreadyInstalled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("reason_class=gate: a service user gate is already installed")
    }
}

impl std::error::Error for ServiceUserGateAlreadyInstalled {}

// A process-wide `OnceLock` rather than a value passed through context. The gate is read
// inside Valence privacy rules, which only see the record, the actor, and the Valence
// handle; Valence has no slot for host ports, and Lepton cannot depend on the host's
// context types. The gate is also one decision fixed at boot that every write path
// (server functions, Boson tasks, Chronon jobs) must share, so one install is the seam.
static GATE: OnceLock<Arc<dyn ServiceUserGate>> = OnceLock::new();

/// Install the process-wide [`ServiceUserGate`]. Call once at host boot, before
/// serving requests.
///
/// Until a gate is installed, nobody can create service users and nobody can manage
/// service users they do not own.
///
/// # Errors
///
/// [`ServiceUserGateAlreadyInstalled`] on a second call; the first gate stays in place.
pub fn install_service_user_gate(
    gate: Arc<dyn ServiceUserGate>,
) -> Result<(), ServiceUserGateAlreadyInstalled> {
    GATE.set(gate).map_err(|_| ServiceUserGateAlreadyInstalled)
}

/// The installed gate, if any.
#[must_use]
pub fn installed_service_user_gate() -> Option<Arc<dyn ServiceUserGate>> {
    GATE.get().cloned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    struct Fixed(bool);

    #[async_trait]
    impl ServiceUserGate for Fixed {
        async fn may_create_service_user(
            &self,
            _v: &Valence,
        ) -> Result<bool, ServiceUserGateError> {
            Ok(self.0)
        }
        async fn may_manage_any_service_user(
            &self,
            _v: &Valence,
        ) -> Result<bool, ServiceUserGateError> {
            Ok(self.0)
        }
    }

    // The only test in this binary that touches the global gate.
    #[test]
    fn install_service_user_gate_twice_sad() {
        let first: Arc<dyn ServiceUserGate> = Arc::new(Fixed(false));
        install_service_user_gate(Arc::clone(&first)).expect("first install");
        assert_eq!(
            install_service_user_gate(Arc::new(Fixed(true))),
            Err(ServiceUserGateAlreadyInstalled)
        );
        let installed = installed_service_user_gate().expect("installed");
        assert!(Arc::ptr_eq(&installed, &first), "first gate stays in place");
    }
}
