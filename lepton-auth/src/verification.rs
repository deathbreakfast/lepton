//! Challenge-keyed verification status for live UI (Photon refetch).
//!
//! # Capability model
//!
//! Pre-auth waiting UIs use Photon `auth = "none"` with a **high-entropy** `challenge_id`
//! (token / factor record id) as the capability key. Knowing the id is equivalent to
//! permission to observe whether that challenge completed — never return secrets, emails,
//! phones, or OTP material. Unknown ids return an empty snapshot (`pending = false`).
//!
//! Hosts must ensure challenge ids remain unguessable (`security::random_token_part`
//! entropy under `ssr`).
//!
//! # Examples
//!
//! ```rust,ignore
//! use lepton_auth::verification::verification_status;
//!
//! let snap = verification_status(challenge_id).await?;
//! if snap.email_verified {
//!     // advance the waiting UI
//! }
//! ```
//!
//! Publish side: [`crate::events`] (`publish_verification_completed` after persist).

use leptos::prelude::*;
use serde::{Deserialize, Serialize};

/// Snapshot of whether a challenge id has been consumed / enabled.
///
/// Contains no secrets — only challenge id and boolean status flags.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // intentional multi-kind status flags for UI
pub struct VerificationStatusSnapshot {
    /// Challenge / token id queried.
    pub challenge_id: String,
    /// Email token was found and `used_at` is set.
    pub email_verified: bool,
    /// Phone token was found and `used_at` is set.
    pub phone_verified: bool,
    /// TOTP factor id was found and `enabled_at` is set.
    pub totp_enabled: bool,
    /// A matching challenge exists but is not yet completed.
    pub pending: bool,
}

impl VerificationStatusSnapshot {
    /// Empty / unknown-challenge snapshot (no pending oracle).
    #[must_use]
    pub fn unknown(challenge_id: impl Into<String>) -> Self {
        Self {
            challenge_id: challenge_id.into(),
            email_verified: false,
            phone_verified: false,
            totp_enabled: false,
            pending: false,
        }
    }
}

/// Look up verification status for `challenge_id` (email / phone token or TOTP factor id).
///
/// For live refetch UIs, wrap with `photon_leptos::synced_resource` and a zero-arg
/// closure that supplies the current challenge id (the `synced` attribute cannot bind
/// parameterized server functions).
///
/// # Errors
///
/// Missing `challenge_id` → args error. Store failures → opaque server error (no inner text).
#[server]
pub async fn verification_status(
    /// Token / factor id to inspect (no secrets returned).
    challenge_id: String,
) -> Result<VerificationStatusSnapshot, ServerFnError> {
    #[cfg(feature = "ssr")]
    {
        verification_status_lookup(challenge_id).await
    }
    #[cfg(not(feature = "ssr"))]
    {
        let _ = challenge_id;
        Err(ServerFnError::ServerError(
            "verification_status requires ssr".into(),
        ))
    }
}

/// Backend lookup used by [`verification_status`] (and unit tests).
#[cfg(feature = "ssr")]
pub async fn verification_status_lookup(
    challenge_id: String,
) -> Result<VerificationStatusSnapshot, ServerFnError> {
    let challenge_id = challenge_id.trim().to_string();
    if challenge_id.is_empty() {
        return Err(ServerFnError::Args("Missing challenge_id".into()));
    }

    let ctx = crate::ssr_support::higgs_ctx().await?;
    let valence = crate::ssr_support::user_valence(&ctx)?;

    lookup_status_with_valence(&challenge_id, &valence).await
}

/// Pure Valence lookup (no Higgs) for tests and internal callers.
#[cfg(feature = "ssr")]
pub async fn lookup_status_with_valence(
    challenge_id: &str,
    valence: &valence::Valence,
) -> Result<VerificationStatusSnapshot, ServerFnError> {
    use lepton_host_adapter::generated::{
        EmailVerificationToken, PhoneVerificationToken, TotpFactor,
    };
    use valence::Model;

    let store_err = || ServerFnError::new("reason_class=status: lookup failed");

    if let Some(token) = EmailVerificationToken::get_used(challenge_id, valence, valence::use_!(r#"In **lepton auth**, we **load Email Verification Token** so the application can decide what to do next in this workflow. The result is used by **lepton auth** logic—not necessarily displayed on a page unless that feature’s UI shows it."#))
        .await
        .map_err(|_| store_err())?
    {
        let mut snap = VerificationStatusSnapshot::unknown(challenge_id);
        if token.used_at().is_some() {
            snap.email_verified = true;
        } else {
            snap.pending = true;
        }
        return Ok(snap);
    }

    if let Some(token) = PhoneVerificationToken::get_used(challenge_id, valence, valence::use_!(r#"In **lepton auth**, we **load Phone Verification Token** so the application can decide what to do next in this workflow. The result is used by **lepton auth** logic—not necessarily displayed on a page unless that feature’s UI shows it."#))
        .await
        .map_err(|_| store_err())?
    {
        let mut snap = VerificationStatusSnapshot::unknown(challenge_id);
        if token.used_at().is_some() {
            snap.phone_verified = true;
        } else {
            snap.pending = true;
        }
        return Ok(snap);
    }

    if let Some(factor) = TotpFactor::get_used(challenge_id, valence, valence::use_!(r#"In **lepton auth**, we **load Totp Factor** so the application can decide what to do next in this workflow. The result is used by **lepton auth** logic—not necessarily displayed on a page unless that feature’s UI shows it."#))
        .await
        .map_err(|_| store_err())?
    {
        let mut snap = VerificationStatusSnapshot::unknown(challenge_id);
        if factor.enabled_at().is_some() {
            snap.totp_enabled = true;
        } else {
            snap.pending = true;
        }
        return Ok(snap);
    }

    Ok(VerificationStatusSnapshot::unknown(challenge_id))
}

#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::*;

    #[test]
    fn verification_status_unknown_challenge_sad() {
        let snap = VerificationStatusSnapshot::unknown("missing-id");
        assert!(!snap.email_verified);
        assert!(!snap.phone_verified);
        assert!(!snap.totp_enabled);
        assert!(!snap.pending);
        assert_eq!(snap.challenge_id, "missing-id");
    }

    #[test]
    fn verification_status_pending_shape_happy_path() {
        let mut snap = VerificationStatusSnapshot::unknown("chal");
        snap.pending = true;
        assert!(snap.pending);
        assert!(!snap.email_verified);
    }
}
