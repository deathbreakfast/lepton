//! Host settings for Lepton identity, set once at boot.
//!
//! Today this holds one setting: how many service users one owner may have. Hosts read
//! it from their own configuration and call [`install_service_users_per_owner`] before
//! serving requests; until then [`service_users_per_owner`] answers
//! [`DEFAULT_SERVICE_USERS_PER_OWNER`].
//!
//! ```
//! use lepton_identity::config::{
//!     install_service_users_per_owner, service_users_per_owner,
//! };
//!
//! install_service_users_per_owner(25).expect("first install");
//! assert_eq!(service_users_per_owner(), 25);
//! assert!(install_service_users_per_owner(5).is_err());
//! ```

use std::fmt;
use std::sync::OnceLock;

/// Service users one owner may have when the host sets no limit.
pub const DEFAULT_SERVICE_USERS_PER_OWNER: usize = 10;

/// [`install_service_users_per_owner`] was called after a limit was already set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceUsersPerOwnerAlreadySet;

impl fmt::Display for ServiceUsersPerOwnerAlreadySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("reason_class=config: the service user limit per owner is already set")
    }
}

impl std::error::Error for ServiceUsersPerOwnerAlreadySet {}

// Process-wide for the same reason as the service user gate: the limit is one host
// decision fixed at boot, and it is read on every create path (server functions, Boson
// tasks, Chronon jobs), none of which share a context Lepton could hang it on.
static SERVICE_USERS_PER_OWNER: OnceLock<usize> = OnceLock::new();

/// Set the most service users one owner may have, active or suspended. Call once at
/// host boot, before serving requests. `0` stops everyone from creating service users.
///
/// # Errors
///
/// [`ServiceUsersPerOwnerAlreadySet`] on a second call; the first limit stays in place.
pub fn install_service_users_per_owner(limit: usize) -> Result<(), ServiceUsersPerOwnerAlreadySet> {
    SERVICE_USERS_PER_OWNER
        .set(limit)
        .map_err(|_| ServiceUsersPerOwnerAlreadySet)
}

/// The limit the host set, or [`DEFAULT_SERVICE_USERS_PER_OWNER`].
#[must_use]
pub fn service_users_per_owner() -> usize {
    SERVICE_USERS_PER_OWNER
        .get()
        .copied()
        .unwrap_or(DEFAULT_SERVICE_USERS_PER_OWNER)
}
