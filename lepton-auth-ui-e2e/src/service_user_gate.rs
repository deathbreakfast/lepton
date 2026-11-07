//! Service user gate for the Playwright host.
//!
//! Any user may create service users. Manage-any goes to the user ids the seed route
//! registers with [`allow_manage_any`]. The gate runs inside privacy evaluation, so it
//! reads no tables.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, OnceLock};

use async_trait::async_trait;
use lepton_identity::service_users::{
    install_service_user_gate, ServiceUserGate, ServiceUserGateError,
};
use valence::Valence;

fn admins() -> &'static Mutex<HashSet<String>> {
    static ADMINS: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    ADMINS.get_or_init(Mutex::default)
}

/// Grant manage-any to a bare user id.
pub fn allow_manage_any(user_id: &str) {
    if let Ok(mut set) = admins().lock() {
        set.insert(user_id.to_string());
    }
}

struct E2eGate;

#[async_trait]
impl ServiceUserGate for E2eGate {
    async fn may_create_service_user(&self, _: &Valence) -> Result<bool, ServiceUserGateError> {
        Ok(true)
    }

    async fn may_manage_any_service_user(
        &self,
        valence: &Valence,
    ) -> Result<bool, ServiceUserGateError> {
        let id = valence.actor().user_id().unwrap_or_default();
        let bare = id.split_once(':').map_or(id, |(_, bare)| bare);
        admins()
            .lock()
            .map(|set| set.contains(bare))
            .map_err(|_| ServiceUserGateError {
                reason_class: "store",
            })
    }
}

/// Install the host gate once at boot.
///
/// # Errors
///
/// When a gate is already installed.
pub fn install() -> anyhow::Result<()> {
    install_service_user_gate(Arc::new(E2eGate)).map_err(|e| anyhow::anyhow!("{e}"))
}
