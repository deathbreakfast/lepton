//! Enabled TOTP factor seed helpers.

use chrono::Utc;
use lepton_host_adapter::generated::TotpFactor;
use valence::{Model, RecordId, Valence};

use crate::error::SeedError;

/// Fixed harness TOTP secret (base32). Must be ≥128 bits for `totp-rs` (RFC 4226).
/// Decodes to ASCII `12345678901234567890` (RFC 6238 test vector).
pub const HARNESS_TOTP_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

pub(super) async fn seed_enabled_totp(
    valence: &Valence,
    user_id: &RecordId,
    secret_sealed: &str,
) -> Result<(), SeedError> {
    let now = Utc::now();
    let factor_id = lepton_auth::security::random_token_part(12);
    let factor = TotpFactor::new(
        user_id.clone(),
        secret_sealed.to_string(),
        None,
        None,
        None,
        Some(now),
        Some(now),
        now,
        now,
    )
    .map_err(|_| SeedError::Persistence {
        operation: "totp_new",
    })?;
    TotpFactor::upsert_used(&factor_id, factor, valence, valence::use_!(r#"While you set up your **authenticator app**, we **save your not-yet-confirmed authenticator setup** for your account—including a **sealed copy of the authenticator secret**—so the next step can check the code from your app and finish turning **two-factor** on. After the QR or setup link at enroll time, the product does not show that secret again; it only keeps the sealed copy to complete **enrollment**."#))
        .await
        .map_err(|_| SeedError::Persistence {
            operation: "totp_upsert",
        })?;
    Ok(())
}
