//! Photon topics for auth verification progress and service user lifecycle changes
//! (live UI refetch).
//!
//! # When to call
//!
//! After Valence persistence succeeds (token consume / factor confirm), call
//! `publish_verification_completed` (`ssr`). Publish is best-effort — failures must not
//! roll back verification. Hosts mount photon-leptos `ws_router` + Origin allowlist
//! separately.
//!
//! Payload is challenge-keyed (`challenge_id` + `kind` only). Never include email, phone,
//! OTP codes, or TOTP secrets.
//!
//! # Examples
//!
//! ```rust,ignore
//! use lepton_auth::events::{publish_verification_completed, VerificationKind};
//!
//! // … Valence consume / confirm succeeded …
//! publish_verification_completed(challenge_id, VerificationKind::Email).await;
//! ```
//!
//! Clients refetch [`crate::verification::verification_status`] keyed by the same
//! high-entropy `challenge_id`.
//!
//! # Service user lifecycle
//!
//! [`crate::service_users`] publishes one `ServiceUserLifecycleChanged` after each create,
//! suspend, resume, or delete is saved, keyed by the owner's user id. The payload holds ids
//! and the change only, never the handle, display name, or description; subscribers
//! refetch through the service user calls, which apply the usual privacy checks.

/// Logical verification channel completed for a challenge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationKind {
    /// Email verification token consumed.
    Email,
    /// Phone / SMS OTP token consumed.
    Phone,
    /// TOTP factor confirmed / enabled.
    Totp,
}

impl VerificationKind {
    /// Wire form used in [`VerificationCompleted::kind`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Totp => "totp",
        }
    }
}

/// What happened to a service user, in [`ServiceUserLifecycleChanged::event`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceUserLifecycleEvent {
    /// The owner created the service user.
    Created,
    /// The service user was suspended.
    Suspended,
    /// The service user was resumed.
    Resumed,
    /// The service user was deleted.
    Deleted,
}

impl ServiceUserLifecycleEvent {
    /// Wire form used in [`ServiceUserLifecycleChanged::event`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Suspended => "suspended",
            Self::Resumed => "resumed",
            Self::Deleted => "deleted",
        }
    }
}

/// Published after a service user lifecycle change is saved (keyed by the owner's user id).
#[cfg(feature = "ssr")]
#[photon::topic(name = "auth.service_user.lifecycle", keyed_by = "owner_id")]
pub struct ServiceUserLifecycleChanged {
    /// Bare user id of the service user's owner.
    pub owner_id: String,
    /// The service user's id (bare UUID).
    pub service_user_id: String,
    /// `"created"`, `"suspended"`, `"resumed"`, or `"deleted"`.
    pub event: String,
}

/// Publish [`ServiceUserLifecycleChanged`].
///
/// Best-effort like [`publish_verification_completed`]: a failure is logged at warn with
/// the ids and never fails the lifecycle call, which has already been saved.
#[cfg(feature = "ssr")]
pub async fn publish_service_user_lifecycle(
    owner_id: String,
    service_user_id: &lepton_identity::service_users::ServiceUserId,
    event: ServiceUserLifecycleEvent,
) {
    #[cfg(any(test, feature = "test-utils"))]
    test_support::record_service_user_publish(
        owner_id.clone(),
        service_user_id.as_str().to_string(),
        event,
    );

    let message = ServiceUserLifecycleChanged {
        owner_id,
        service_user_id: service_user_id.as_str().to_string(),
        event: event.as_str().to_string(),
    };
    if let Err(e) = message.publish().await {
        tracing::warn!(
            target: "lepton.service_user",
            service_user_id = service_user_id.as_str(),
            event = event.as_str(),
            error = %e,
            "auth.service_user.lifecycle publish failed (ignored)"
        );
    }
}

/// Published after a verification challenge succeeds (keyed by `challenge_id`).
#[cfg(feature = "ssr")]
#[photon::topic(name = "auth.verification.completed", keyed_by = "challenge_id")]
pub struct VerificationCompleted {
    /// Token / challenge id that was verified.
    pub challenge_id: String,
    /// `"email"`, `"phone"`, or `"totp"`.
    pub kind: String,
}

/// Short opaque fingerprint for logs (never log full challenge ids / OTP capability keys).
#[cfg(feature = "ssr")]
#[must_use]
pub fn challenge_id_fingerprint(challenge_id: &str) -> String {
    use std::fmt::Write;
    let bytes = challenge_id.as_bytes();
    let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        acc ^= u64::from(*b);
        acc = acc.wrapping_mul(0x0100_0000_01b3);
    }
    let mut out = String::with_capacity(16);
    let _ = write!(out, "{acc:016x}");
    out
}

/// Publish [`VerificationCompleted`].
///
/// Publish failures are logged at warn (fingerprint only) and **do not** fail the caller —
/// verification persistence is the source of truth; Photon is best-effort for live UI.
#[cfg(feature = "ssr")]
pub async fn publish_verification_completed(challenge_id: String, kind: VerificationKind) {
    #[cfg(any(test, feature = "test-utils"))]
    test_support::record_publish(challenge_id.clone(), kind);

    let event = VerificationCompleted {
        challenge_id: challenge_id.clone(),
        kind: kind.as_str().to_string(),
    };
    if let Err(e) = event.publish().await {
        tracing::warn!(
            challenge_fp = %challenge_id_fingerprint(&challenge_id),
            kind = kind.as_str(),
            error = %e,
            "auth.verification.completed publish failed (ignored)"
        );
    }
}

/// Publish capture for unit / integration tests (`test-utils` feature or `cfg(test)`).
#[cfg(all(feature = "ssr", any(test, feature = "test-utils")))]
pub mod test_support {
    use super::{ServiceUserLifecycleEvent, VerificationKind};
    use std::sync::{Mutex, OnceLock};

    /// A captured service user publish: owner id, service user id, event.
    pub type ServiceUserPublish = (String, String, ServiceUserLifecycleEvent);

    fn service_user_log() -> &'static Mutex<Vec<ServiceUserPublish>> {
        static LOG: OnceLock<Mutex<Vec<ServiceUserPublish>>> = OnceLock::new();
        LOG.get_or_init(|| Mutex::new(Vec::new()))
    }

    pub(super) fn record_service_user_publish(
        owner_id: String,
        service_user_id: String,
        event: ServiceUserLifecycleEvent,
    ) {
        if let Ok(mut guard) = service_user_log().lock() {
            guard.push((owner_id, service_user_id, event));
        }
    }

    /// Drain recorded service user lifecycle publishes.
    #[must_use]
    pub fn take_service_user_published() -> Vec<ServiceUserPublish> {
        service_user_log()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
            .collect()
    }

    fn log() -> &'static Mutex<Vec<(String, VerificationKind)>> {
        static LOG: OnceLock<Mutex<Vec<(String, VerificationKind)>>> = OnceLock::new();
        LOG.get_or_init(|| Mutex::new(Vec::new()))
    }

    pub(super) fn record_publish(challenge_id: String, kind: VerificationKind) {
        if let Ok(mut guard) = log().lock() {
            guard.push((challenge_id, kind));
        }
    }

    /// Drain recorded publishes.
    #[must_use]
    pub fn take_published() -> Vec<(String, VerificationKind)> {
        log()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
            .collect()
    }
}

#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn photon_publish_records_on_success_path_happy_path() {
        let _ = test_support::take_published();
        publish_verification_completed("chal-abc".into(), VerificationKind::Email).await;
        let got = test_support::take_published();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "chal-abc");
        assert_eq!(got[0].1, VerificationKind::Email);
    }

    #[tokio::test]
    async fn service_user_publish_records_ids_only_happy() {
        let id = lepton_identity::service_users::ServiceUserId::new_v4();
        publish_service_user_lifecycle(
            "unit-owner".into(),
            &id,
            ServiceUserLifecycleEvent::Suspended,
        )
        .await;
        let got: Vec<_> = test_support::take_service_user_published()
            .into_iter()
            .filter(|(owner, _, _)| owner == "unit-owner")
            .collect();
        assert_eq!(
            got,
            [(
                "unit-owner".to_string(),
                id.as_str().to_string(),
                ServiceUserLifecycleEvent::Suspended
            )]
        );
    }

    #[test]
    fn challenge_id_fingerprint_stable_and_not_plaintext() {
        let fp = challenge_id_fingerprint("super-secret-challenge");
        assert_eq!(fp.len(), 16);
        assert!(!fp.contains("secret"));
        assert_eq!(fp, challenge_id_fingerprint("super-secret-challenge"));
    }
}
