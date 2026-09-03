//! AEAD seal/unseal for TOTP shared secrets stored on `TotpFactor.secret_sealed`.
//!
//! Format: `v1:<base64(nonce || ciphertext)>` using XChaCha20-Poly1305.
//! Legacy rows without the `v1:` prefix are treated as plaintext base32 and
//! re-sealed on the next successful verify (lazy migration).
//!
//! Key source: `LEPTON_TOTP_SEAL_KEY` (64 hex chars → 32 bytes). Tests may set
//! `LEPTON_TOTP_ALLOW_TEST_SEAL_KEY=1` to use a fixed non-production key.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};

use crate::factor::FactorChallengeError;

const SEAL_PREFIX: &str = "v1:";
const SEAL_KEY_ENV: &str = "LEPTON_TOTP_SEAL_KEY";
const ALLOW_TEST_KEY_ENV: &str = "LEPTON_TOTP_ALLOW_TEST_SEAL_KEY";
/// Fixed 32-byte key for deterministic unit tests only.
const TEST_SEAL_KEY: [u8; 32] = *b"lepton-totp-test-seal-key!!32byt";

fn load_seal_key() -> Result<[u8; 32], FactorChallengeError> {
    match std::env::var(SEAL_KEY_ENV) {
        Ok(hex) => {
            let trimmed = hex.trim();
            if trimmed.len() != 64 {
                return Err(FactorChallengeError::TotpSecret);
            }
            let mut out = [0u8; 32];
            for (i, chunk) in trimmed.as_bytes().chunks(2).enumerate() {
                let s = std::str::from_utf8(chunk).map_err(|_| FactorChallengeError::TotpSecret)?;
                out[i] = u8::from_str_radix(s, 16).map_err(|_| FactorChallengeError::TotpSecret)?;
            }
            Ok(out)
        }
        Err(_) if std::env::var(ALLOW_TEST_KEY_ENV).as_deref() == Ok("1") => Ok(TEST_SEAL_KEY),
        #[cfg(test)]
        Err(_) => Ok(TEST_SEAL_KEY),
        #[cfg(not(test))]
        Err(_) => Err(FactorChallengeError::TotpSecret),
    }
}

/// Whether `secret_sealed` already uses the AEAD envelope.
#[must_use]
pub fn is_sealed_envelope(secret_sealed: &str) -> bool {
    secret_sealed.starts_with(SEAL_PREFIX)
}

/// Seal a raw base32 TOTP secret into the `v1:` AEAD envelope.
///
/// # Errors
///
/// [`FactorChallengeError::TotpSecret`] when the seal key is missing/invalid or
/// AEAD fails (never includes key or plaintext).
pub fn seal_totp_secret(base32_secret: &str) -> Result<String, FactorChallengeError> {
    let key_bytes = load_seal_key()?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: base32_secret.as_bytes(),
                aad: b"lepton.totp.secret",
            },
        )
        .map_err(|_| FactorChallengeError::TotpSecret)?;
    let mut packed = Vec::with_capacity(24 + ciphertext.len());
    packed.extend_from_slice(&nonce);
    packed.extend_from_slice(&ciphertext);
    Ok(format!("{SEAL_PREFIX}{}", B64.encode(packed)))
}

/// Reveal the base32 TOTP secret from a sealed envelope or legacy plaintext row.
///
/// # Errors
///
/// [`FactorChallengeError::TotpSecret`] on decode/decrypt failure.
pub fn unseal_totp_secret(secret_sealed: &str) -> Result<String, FactorChallengeError> {
    let trimmed = secret_sealed.trim();
    if !is_sealed_envelope(trimmed) {
        return Ok(trimmed.to_string());
    }
    let b64 = &trimmed[SEAL_PREFIX.len()..];
    let packed = B64
        .decode(b64.as_bytes())
        .map_err(|_| FactorChallengeError::TotpSecret)?;
    if packed.len() <= 24 {
        return Err(FactorChallengeError::TotpSecret);
    }
    let (nonce, ciphertext) = packed.split_at(24);
    let key_bytes = load_seal_key()?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: b"lepton.totp.secret",
            },
        )
        .map_err(|_| FactorChallengeError::TotpSecret)?;
    String::from_utf8(plaintext).map_err(|_| FactorChallengeError::TotpSecret)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn seal_roundtrip_happy() {
        std::env::set_var(ALLOW_TEST_KEY_ENV, "1");
        let sealed = seal_totp_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").expect("seal");
        assert!(is_sealed_envelope(&sealed));
        let open = unseal_totp_secret(&sealed).expect("unseal");
        assert_eq!(open, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    }

    #[test]
    fn legacy_plaintext_passthrough() {
        let open = unseal_totp_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").expect("legacy");
        assert_eq!(open, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert!(!is_sealed_envelope("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
    }
}
