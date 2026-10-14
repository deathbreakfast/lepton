//! Process-wide ring of TOTP seal keys, one per key version.
//!
//! Hosts that keep the seal key in Neutrino build a [`TotpKeyRing`] from every
//! stored key version and [`install_key_ring`] it. Sealing then uses the current
//! version and writes `v2:<version>:…` envelopes; unsealing picks the key by the
//! version in the envelope, so rows sealed under an older key keep working after
//! a rotation and re-seal on their next successful verify.
//!
//! With no ring installed, sealing falls back to the single
//! `LEPTON_TOTP_SEAL_KEY` env key and `v1:` envelopes, which is the behavior
//! before key rotation existed.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

/// Raw 32-byte XChaCha20-Poly1305 key.
pub type SealKeyBytes = [u8; 32];

/// Why a [`TotpKeyRing`] could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyRingError {
    /// The ring has no keys.
    #[error("TOTP key ring has no keys")]
    Empty,
    /// The declared current version is not among the supplied keys.
    #[error("TOTP key ring current version {current} has no key")]
    MissingCurrent {
        /// Declared current key version.
        current: u32,
    },
}

/// Seal keys by version, with one version marked current.
///
/// Key bytes are never printed: `Debug` shows versions only.
#[derive(Clone)]
pub struct TotpKeyRing {
    current: u32,
    keys: BTreeMap<u32, SealKeyBytes>,
}

impl std::fmt::Debug for TotpKeyRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpKeyRing")
            .field("current", &self.current)
            .field("versions", &self.keys.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl TotpKeyRing {
    /// Build a ring from `(version, key)` pairs and the version to seal with.
    ///
    /// # Errors
    ///
    /// [`KeyRingError::Empty`] when no keys are supplied, and
    /// [`KeyRingError::MissingCurrent`] when `current` is not among them.
    pub fn new(
        current: u32,
        keys: impl IntoIterator<Item = (u32, SealKeyBytes)>,
    ) -> Result<Self, KeyRingError> {
        let keys: BTreeMap<u32, SealKeyBytes> = keys.into_iter().collect();
        if keys.is_empty() {
            return Err(KeyRingError::Empty);
        }
        if !keys.contains_key(&current) {
            return Err(KeyRingError::MissingCurrent { current });
        }
        Ok(Self { current, keys })
    }

    /// Version new envelopes are sealed with.
    #[must_use]
    pub const fn current_version(&self) -> u32 {
        self.current
    }

    /// Key for `version`, when the ring still holds it.
    #[must_use]
    pub fn key(&self, version: u32) -> Option<&SealKeyBytes> {
        self.keys.get(&version)
    }

    /// Versions held, ascending.
    #[must_use]
    pub fn versions(&self) -> Vec<u32> {
        self.keys.keys().copied().collect()
    }
}

type ResyncHook = Arc<dyn Fn() + Send + Sync>;

static RING: RwLock<Option<Arc<TotpKeyRing>>> = RwLock::new(None);
static RESYNC_HOOK: RwLock<Option<ResyncHook>> = RwLock::new(None);

/// Install (or replace) the process-wide ring. Takes effect on the next seal or unseal.
pub fn install_key_ring(ring: TotpKeyRing) {
    // A poisoned lock only means a previous holder panicked; the Option inside is still valid.
    let mut slot = RING
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *slot = Some(Arc::new(ring));
}

/// The installed ring, if any.
#[must_use]
pub fn installed_key_ring() -> Option<Arc<TotpKeyRing>> {
    RING.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Register the callback that runs when an envelope names a key
/// version this process has not loaded yet (another process rotated first).
///
/// The callback must return quickly and never block on I/O; hosts use it to wake
/// their refresher.
pub fn set_resync_hook(hook: impl Fn() + Send + Sync + 'static) {
    let mut slot = RESYNC_HOOK
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *slot = Some(Arc::new(hook));
}

/// Ask the host to reload keys. No-op when no hook is registered.
pub(crate) fn request_resync() {
    let hook = RESYNC_HOOK
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn new_rejects_empty_ring() {
        let err = TotpKeyRing::new(1, []).expect_err("empty");
        assert_eq!(err, KeyRingError::Empty);
    }

    #[test]
    fn new_rejects_current_without_key() {
        let err = TotpKeyRing::new(3, [(1, [1u8; 32]), (2, [2u8; 32])]).expect_err("missing");
        assert_eq!(err, KeyRingError::MissingCurrent { current: 3 });
    }

    #[test]
    fn debug_lists_versions_never_key_bytes() {
        let ring = TotpKeyRing::new(2, [(1, [0xAB; 32]), (2, [0xCD; 32])]).expect("ring");
        let shown = format!("{ring:?}");
        assert!(shown.contains("current: 2"));
        assert!(!shown.contains("171") && !shown.contains("205") && !shown.contains("AB"));
        assert_eq!(ring.versions(), vec![1, 2]);
    }
}
