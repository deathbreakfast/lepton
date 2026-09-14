//! TOTP enroll / disable / recovery codes.

use chrono::Utc;
use lepton_host_adapter::auth::hash_password;
use lepton_host_adapter::generated::{TotpFactor, TotpRecoveryCode, User};
use rand_core::{OsRng, RngCore};
use valence::{Model, RecordId, Valence};

use super::TotpEnrollError;
use crate::factor::verify_totp_against_sealed;
use crate::security::random_token_part;

fn bare_id(record: &RecordId) -> String {
    valence::extract_id_from_record(record).unwrap_or_else(|_| record.id().to_string())
}

/// Pending enroll result: factor id + otpauth URI for QR display.
#[derive(Clone, Debug)]
pub struct PendingTotpEnroll {
    /// Valence `totp_factor` id.
    pub factor_id: String,
    /// `otpauth://` URI for authenticator apps.
    pub otpauth_uri: String,
}

/// Build an `otpauth://` URI for authenticator apps.
///
/// `account_label` and `issuer` are percent-encoded. Empty account → `"user"`;
/// empty issuer → `"App"` (hosts should pass their site/product name).
#[must_use]
pub fn otpauth_uri_for(account_label: &str, issuer: &str, secret_sealed: &str) -> String {
    let label = account_label.trim();
    let label = if label.is_empty() { "user" } else { label };
    let issuer = issuer.trim();
    let issuer = if issuer.is_empty() { "App" } else { issuer };
    let encoded_label = urlencoding::encode(label);
    let encoded_issuer = urlencoding::encode(issuer);
    format!(
        "otpauth://totp/{encoded_issuer}:{encoded_label}?secret={secret_sealed}&issuer={encoded_issuer}&algorithm=SHA1&digits=6&period=30"
    )
}

/// Begin TOTP enrollment: create unconfirmed factor with sealed secret.
///
/// `account_label` appears in the otpauth URI (e.g. email). `issuer` is the site /
/// product name shown in authenticator apps (pass your brand; empty → `"App"`).
/// Empty account labels fall back to `"user"`.
///
/// # Errors
///
/// [`TotpEnrollError::AlreadyEnabled`] when an enabled factor exists.
pub async fn begin_totp_enroll(
    valence: &Valence,
    user: &RecordId,
    account_label: &str,
    issuer: &str,
) -> Result<PendingTotpEnroll, TotpEnrollError> {
    use totp_rs::{Algorithm, Secret, TOTP};

    let uid = bare_id(user);
    if User::get(&uid, valence)
        .await
        .map_err(|_| TotpEnrollError::Store)?
        .is_none()
    {
        #[cfg(feature = "spectra")]
        crate::spectra_emit::totp(
            crate::spectra_emit::TotpOperation::BeginEnroll,
            crate::spectra_emit::AuthOutcome::Failure,
            "user",
        );
        return Err(TotpEnrollError::UserMissing);
    }

    let existing = TotpFactor::get_from_user_id(&uid, valence)
        .await
        .map_err(|_| TotpEnrollError::Store)?;
    if existing.iter().any(|f| f.enabled_at().is_some()) {
        #[cfg(feature = "spectra")]
        crate::spectra_emit::totp(
            crate::spectra_emit::TotpOperation::BeginEnroll,
            crate::spectra_emit::AuthOutcome::Failure,
            "totp_already_enabled",
        );
        return Err(TotpEnrollError::AlreadyEnabled);
    }

    // 20 random bytes → base32 for otpauth, then AEAD-sealed at rest.
    let mut raw = [0u8; 20];
    OsRng.fill_bytes(&mut raw);
    let secret = Secret::Raw(raw.to_vec());
    let secret_b32 = secret.to_encoded().to_string();
    let _totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes().map_err(|_| TotpEnrollError::Store)?,
    )
    .map_err(|_| TotpEnrollError::Store)?;
    let otpauth_uri = otpauth_uri_for(account_label, issuer, &secret_b32);
    let secret_sealed =
        crate::totp::seal::seal_totp_secret(&secret_b32).map_err(|_| TotpEnrollError::Store)?;

    let now = Utc::now();
    let factor_id = random_token_part(12);
    let factor = TotpFactor::new(
        user.clone(),
        secret_sealed,
        None,
        None,
        None,
        None,
        None,
        now,
        now,
    )
    .map_err(|_| TotpEnrollError::Store)?;
    TotpFactor::upsert(&factor_id, factor, valence)
        .await
        .map_err(|_| TotpEnrollError::Store)?;

    #[cfg(feature = "spectra")]
    crate::spectra_emit::totp(
        crate::spectra_emit::TotpOperation::BeginEnroll,
        crate::spectra_emit::AuthOutcome::Success,
        "none",
    );
    Ok(PendingTotpEnroll {
        factor_id,
        otpauth_uri,
    })
}

/// Confirm enroll with a TOTP code; sets `enabled_at` / `confirmed_at`.
///
/// # Errors
///
/// [`TotpEnrollError::Mismatch`] on bad code; factor/user/store otherwise.
pub async fn confirm_totp_enroll(
    valence: &Valence,
    user: &RecordId,
    factor_id: &str,
    code: &str,
) -> Result<(), TotpEnrollError> {
    let factor = match TotpFactor::get(factor_id, valence).await {
        Ok(Some(f)) => f,
        Ok(None) => {
            #[cfg(feature = "spectra")]
            crate::spectra_emit::totp(
                crate::spectra_emit::TotpOperation::ConfirmEnroll,
                crate::spectra_emit::AuthOutcome::Failure,
                "factor",
            );
            return Err(TotpEnrollError::FactorMissing);
        }
        Err(_) => {
            #[cfg(feature = "spectra")]
            crate::spectra_emit::totp(
                crate::spectra_emit::TotpOperation::ConfirmEnroll,
                crate::spectra_emit::AuthOutcome::Failure,
                "store",
            );
            return Err(TotpEnrollError::Store);
        }
    };
    if bare_id(factor.user()) != bare_id(user) {
        #[cfg(feature = "spectra")]
        crate::spectra_emit::totp(
            crate::spectra_emit::TotpOperation::ConfirmEnroll,
            crate::spectra_emit::AuthOutcome::Failure,
            "factor",
        );
        return Err(TotpEnrollError::FactorMissing);
    }
    if verify_totp_against_sealed(factor.secret_sealed(), code, None).is_err() {
        #[cfg(feature = "spectra")]
        crate::spectra_emit::totp(
            crate::spectra_emit::TotpOperation::ConfirmEnroll,
            crate::spectra_emit::AuthOutcome::Failure,
            "mismatch",
        );
        return Err(TotpEnrollError::Mismatch);
    }
    let now = Utc::now();
    factor
        .get_mutable(valence)
        .set_confirmed_at(now)
        .map_err(|_| TotpEnrollError::Store)?
        .set_enabled_at(now)
        .map_err(|_| TotpEnrollError::Store)?
        .set_updated_at(now)
        .map_err(|_| TotpEnrollError::Store)?
        .commit()
        .await
        .map_err(|_| TotpEnrollError::Store)?;
    #[cfg(feature = "spectra")]
    crate::spectra_emit::totp(
        crate::spectra_emit::TotpOperation::ConfirmEnroll,
        crate::spectra_emit::AuthOutcome::Success,
        "none",
    );
    Ok(())
}

/// Physically remove a row without the host Model deletion dispatcher (embedded / tests).
async fn physical_delete(
    valence: &Valence,
    table: &str,
    bare: &str,
) -> Result<(), TotpEnrollError> {
    let backend = valence
        .backend_for_table(table)
        .map_err(|_| TotpEnrollError::Store)?;
    backend
        .delete_record(table, bare)
        .await
        .map_err(|_| TotpEnrollError::Store)?;
    valence::read_cache::invalidate(table, bare);
    Ok(())
}

/// Disable TOTP for `user`: delete factors and invalidate recovery codes.
///
/// Uses in-process physical deletes (same approach as account wipe) so hosts that
/// have not registered a Valence Model deletion dispatcher still succeed.
///
/// # Errors
///
/// Store failures.
pub async fn disable_totp(valence: &Valence, user: &RecordId) -> Result<(), TotpEnrollError> {
    let uid = bare_id(user);
    let now = Utc::now();
    let recovery = TotpRecoveryCode::get_from_user_id(&uid, valence)
        .await
        .map_err(|_| TotpEnrollError::Store)?;
    for code in recovery {
        if code.used_at().is_none() {
            code.get_mutable(valence)
                .set_used_at(now)
                .map_err(|_| TotpEnrollError::Store)?
                .commit()
                .await
                .map_err(|_| TotpEnrollError::Store)?;
        }
        if let Some(id) = code.id().map(bare_id) {
            physical_delete(valence, "totp_recovery_code", &id).await?;
        }
    }

    let factors = TotpFactor::get_from_user_id(&uid, valence)
        .await
        .map_err(|_| TotpEnrollError::Store)?;
    for factor in factors {
        let Some(id) = factor.id().map(bare_id) else {
            continue;
        };
        physical_delete(valence, "totp_factor", &id).await?;
    }
    #[cfg(feature = "spectra")]
    crate::spectra_emit::totp(
        crate::spectra_emit::TotpOperation::Disable,
        crate::spectra_emit::AuthOutcome::Success,
        "none",
    );
    Ok(())
}

fn verify_phc(plaintext: &str, phc: &str) -> bool {
    use argon2::{password_hash::PasswordHash, PasswordVerifier};

    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    argon2::Argon2::default()
        .verify_password(plaintext.as_bytes(), &parsed)
        .is_ok()
}

/// Consume one unused recovery code for `user` (sets `used_at`).
///
/// Wrong, empty, already-used, or unknown codes all return
/// [`TotpEnrollError::Mismatch`] (no used-vs-wrong oracle). Never logs plaintext.
///
/// # Errors
///
/// [`TotpEnrollError::Mismatch`] when no unused code matches; [`TotpEnrollError::Store`]
/// on persistence failure.
pub async fn consume_totp_recovery_code(
    valence: &Valence,
    user: &RecordId,
    code: &str,
) -> Result<(), TotpEnrollError> {
    let trimmed = code.trim();
    if trimmed.is_empty() {
        #[cfg(feature = "spectra")]
        crate::spectra_emit::totp(
            crate::spectra_emit::TotpOperation::ConsumeRecovery,
            crate::spectra_emit::AuthOutcome::Failure,
            "mismatch",
        );
        return Err(TotpEnrollError::Mismatch);
    }

    let uid = bare_id(user);
    let rows = TotpRecoveryCode::get_from_user_id(&uid, valence)
        .await
        .map_err(|_| TotpEnrollError::Store)?;

    let mut matched = None;
    for row in rows {
        if row.used_at().is_some() {
            continue;
        }
        if verify_phc(trimmed, row.code_hash()) {
            matched = Some(row);
            break;
        }
    }

    let Some(row) = matched else {
        tracing::info!(
            operation = "totp.consume_recovery",
            outcome = "mismatch",
            "recovery code rejected"
        );
        #[cfg(feature = "spectra")]
        crate::spectra_emit::totp(
            crate::spectra_emit::TotpOperation::ConsumeRecovery,
            crate::spectra_emit::AuthOutcome::Failure,
            "mismatch",
        );
        return Err(TotpEnrollError::Mismatch);
    };

    let now = Utc::now();
    row.get_mutable(valence)
        .set_used_at(now)
        .map_err(|_| TotpEnrollError::Store)?
        .commit()
        .await
        .map_err(|_| TotpEnrollError::Store)?;

    tracing::info!(
        operation = "totp.consume_recovery",
        outcome = "ok",
        "recovery code consumed"
    );
    #[cfg(feature = "spectra")]
    crate::spectra_emit::totp(
        crate::spectra_emit::TotpOperation::ConsumeRecovery,
        crate::spectra_emit::AuthOutcome::Success,
        "none",
    );
    Ok(())
}

/// Replace recovery codes; returns plaintext codes once.
///
/// # Errors
///
/// Store failures. Never logs plaintext codes.
pub async fn regenerate_totp_recovery_codes(
    valence: &Valence,
    user: &RecordId,
) -> Result<Vec<String>, TotpEnrollError> {
    let uid = bare_id(user);
    let existing = TotpRecoveryCode::get_from_user_id(&uid, valence)
        .await
        .map_err(|_| TotpEnrollError::Store)?;
    let now = Utc::now();
    for code in existing {
        code.get_mutable(valence)
            .set_used_at(now)
            .map_err(|_| TotpEnrollError::Store)?
            .commit()
            .await
            .map_err(|_| TotpEnrollError::Store)?;
    }

    let mut plain = Vec::with_capacity(8);
    for _ in 0..8 {
        let code = random_token_part(8);
        let hash = hash_password(&code).map_err(|_| TotpEnrollError::Store)?;
        let row = TotpRecoveryCode::new(user.clone(), hash, None, now)
            .map_err(|_| TotpEnrollError::Store)?;
        let id = random_token_part(12);
        TotpRecoveryCode::upsert(&id, row, valence)
            .await
            .map_err(|_| TotpEnrollError::Store)?;
        plain.push(code);
    }
    #[cfg(feature = "spectra")]
    crate::spectra_emit::totp(
        crate::spectra_emit::TotpOperation::RegenerateRecovery,
        crate::spectra_emit::AuthOutcome::Success,
        "none",
    );
    Ok(plain)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::otpauth_uri_for;

    #[test]
    fn otpauth_uri_includes_encoded_account_label_happy() {
        let uri = otpauth_uri_for(
            "you@example.com",
            "Acme Site",
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        );
        assert!(uri.starts_with("otpauth://totp/Acme%20Site:you%40example.com?"));
        assert!(uri.contains("secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
        assert!(uri.contains("issuer=Acme%20Site"));
    }

    #[test]
    fn otpauth_uri_empty_label_and_issuer_defaults() {
        let uri = otpauth_uri_for("  ", "  ", "SECRET");
        assert!(uri.starts_with("otpauth://totp/App:user?"));
        assert!(uri.contains("issuer=App"));
    }
}
