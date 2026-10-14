//! AEAD seal/unseal for TOTP shared secrets stored on `TotpFactor.secret_sealed`.
//!
//! Formats, both XChaCha20-Poly1305 over `nonce(24) || ciphertext`, base64:
//!
//! - `v1:<b64>`: sealed with the single env key; by convention key version 1.
//! - `v2:<version>:<b64>`: sealed with that version from the installed
//!   [`TotpKeyRing`]. The version is bound into the AEAD associated data, so
//!   relabeling an envelope to another version fails to open.
//!
//! Legacy rows with neither prefix are plaintext base32 and are sealed on the
//! next successful verify. Rows under a key version other than the ring's
//! current one re-seal the same way (see [`needs_reseal`]).
//!
//! Key source with no ring installed: `LEPTON_TOTP_SEAL_KEY` (64 hex chars → 32
//! bytes). Tests may set `LEPTON_TOTP_ALLOW_TEST_SEAL_KEY=1` to use a fixed
//! non-production key.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};

use super::key_ring::{installed_key_ring, request_resync, SealKeyBytes, TotpKeyRing};
use crate::factor::FactorChallengeError;

const V1_PREFIX: &str = "v1:";
const V2_PREFIX: &str = "v2:";
const SEAL_KEY_ENV: &str = "LEPTON_TOTP_SEAL_KEY";
const ALLOW_TEST_KEY_ENV: &str = "LEPTON_TOTP_ALLOW_TEST_SEAL_KEY";
const AAD_V1: &[u8] = b"lepton.totp.secret";
/// Key version the env key stands for.
const ENV_KEY_VERSION: u32 = 1;
/// Fixed 32-byte key for deterministic unit tests only.
const TEST_SEAL_KEY: SealKeyBytes = *b"lepton-totp-test-seal-key!!32byt";

fn load_env_seal_key() -> Result<SealKeyBytes, FactorChallengeError> {
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

/// Parsed envelope header: key version and the base64 payload.
struct Envelope<'a> {
    version: u32,
    b64: &'a str,
    aad: Vec<u8>,
}

fn parse_envelope(sealed: &str) -> Option<Envelope<'_>> {
    if let Some(b64) = sealed.strip_prefix(V1_PREFIX) {
        return Some(Envelope {
            version: ENV_KEY_VERSION,
            b64,
            aad: AAD_V1.to_vec(),
        });
    }
    let rest = sealed.strip_prefix(V2_PREFIX)?;
    let (version, b64) = rest.split_once(':')?;
    let version: u32 = version.parse().ok()?;
    Some(Envelope {
        version,
        b64,
        aad: aad_v2(version),
    })
}

fn aad_v2(version: u32) -> Vec<u8> {
    format!("lepton.totp.secret.v2:{version}").into_bytes()
}

/// Whether `secret_sealed` already uses an AEAD envelope (`v1:` or `v2:`).
#[must_use]
pub fn is_sealed_envelope(secret_sealed: &str) -> bool {
    secret_sealed.starts_with(V1_PREFIX) || secret_sealed.starts_with(V2_PREFIX)
}

/// Key version an envelope was sealed under, or `None` for legacy plaintext or
/// an unparseable header.
#[must_use]
pub fn envelope_key_version(secret_sealed: &str) -> Option<u32> {
    parse_envelope(secret_sealed.trim()).map(|e| e.version)
}

/// Whether a successful verify should re-seal this value: legacy plaintext, or
/// an envelope under a key version other than the installed ring's current one.
///
/// With no ring installed only plaintext qualifies, matching the single-key
/// behavior from before rotation existed.
#[must_use]
pub fn needs_reseal(secret_sealed: &str) -> bool {
    needs_reseal_with(installed_key_ring().as_deref(), secret_sealed)
}

fn needs_reseal_with(ring: Option<&TotpKeyRing>, secret_sealed: &str) -> bool {
    match (envelope_key_version(secret_sealed), ring) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(version), Some(ring)) => version != ring.current_version(),
    }
}

/// Seal a raw base32 TOTP secret under the ring's current key (`v2:`), or the
/// env key (`v1:`) when no ring is installed.
///
/// # Errors
///
/// [`FactorChallengeError::TotpSecret`] when the seal key is missing/invalid or
/// AEAD fails (never includes key or plaintext).
pub fn seal_totp_secret(base32_secret: &str) -> Result<String, FactorChallengeError> {
    seal_with(installed_key_ring().as_deref(), base32_secret)
}

fn seal_with(
    ring: Option<&TotpKeyRing>,
    base32_secret: &str,
) -> Result<String, FactorChallengeError> {
    let (prefix, aad, key_bytes) = match ring {
        Some(ring) => {
            let version = ring.current_version();
            let key = *ring.key(version).ok_or(FactorChallengeError::TotpSecret)?;
            (format!("{V2_PREFIX}{version}:"), aad_v2(version), key)
        }
        None => (V1_PREFIX.to_string(), AAD_V1.to_vec(), load_env_seal_key()?),
    };
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: base32_secret.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|_| FactorChallengeError::TotpSecret)?;
    let mut packed = Vec::with_capacity(24 + ciphertext.len());
    packed.extend_from_slice(&nonce);
    packed.extend_from_slice(&ciphertext);
    Ok(format!("{prefix}{}", B64.encode(packed)))
}

/// Reveal the base32 TOTP secret from a sealed envelope or legacy plaintext row.
///
/// An envelope naming a key version this process has not loaded asks the host to
/// resync (see [`super::key_ring::set_resync_hook`]) and fails closed; the caller
/// retries on the user's next attempt.
///
/// # Errors
///
/// [`FactorChallengeError::TotpSecret`] on decode/decrypt failure or unknown key version.
pub fn unseal_totp_secret(secret_sealed: &str) -> Result<String, FactorChallengeError> {
    unseal_with(installed_key_ring().as_deref(), secret_sealed)
}

fn unseal_with(
    ring: Option<&TotpKeyRing>,
    secret_sealed: &str,
) -> Result<String, FactorChallengeError> {
    let trimmed = secret_sealed.trim();
    if !is_sealed_envelope(trimmed) {
        return Ok(trimmed.to_string());
    }
    let envelope = parse_envelope(trimmed).ok_or(FactorChallengeError::TotpSecret)?;
    let packed = B64
        .decode(envelope.b64.as_bytes())
        .map_err(|_| FactorChallengeError::TotpSecret)?;
    if packed.len() <= 24 {
        return Err(FactorChallengeError::TotpSecret);
    }
    let (nonce, ciphertext) = packed.split_at(24);
    let key_bytes = match ring {
        Some(ring) => match ring.key(envelope.version) {
            Some(key) => *key,
            None if envelope.version == ENV_KEY_VERSION => load_env_seal_key()?,
            None => {
                request_resync();
                return Err(FactorChallengeError::TotpSecret);
            }
        },
        None if envelope.version == ENV_KEY_VERSION => load_env_seal_key()?,
        None => return Err(FactorChallengeError::TotpSecret),
    };
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &envelope.aad,
            },
        )
        .map_err(|_| FactorChallengeError::TotpSecret)?;
    String::from_utf8(plaintext).map_err(|_| FactorChallengeError::TotpSecret)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::totp::key_ring::set_resync_hook;

    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn ring(current: u32, versions: &[u32]) -> TotpKeyRing {
        TotpKeyRing::new(
            current,
            versions
                .iter()
                .map(|v| (*v, [u8::try_from(*v).unwrap(); 32])),
        )
        .expect("ring")
    }

    #[test]
    fn seal_roundtrip_happy() {
        std::env::set_var(ALLOW_TEST_KEY_ENV, "1");
        let sealed = seal_totp_secret(SECRET).expect("seal");
        assert!(is_sealed_envelope(&sealed));
        let open = unseal_totp_secret(&sealed).expect("unseal");
        assert_eq!(open, SECRET);
    }

    #[test]
    fn legacy_plaintext_passthrough() {
        let open = unseal_totp_secret(SECRET).expect("legacy");
        assert_eq!(open, SECRET);
        assert!(!is_sealed_envelope(SECRET));
    }

    #[test]
    fn corrupt_sealed_secret_fails_closed_sad() {
        std::env::set_var(ALLOW_TEST_KEY_ENV, "1");
        let err = unseal_totp_secret("v1:not-valid-base64!!!").expect_err("corrupt");
        assert!(matches!(err, FactorChallengeError::TotpSecret));
        let msg = err.to_string();
        assert_eq!(err.reason_class(), "totp_secret");
        assert!(!msg.contains("not-valid-base64"));
        assert!(!msg.to_lowercase().contains("panic"));
    }

    #[test]
    fn seal_v2_roundtrip_names_current_version() {
        let r = ring(2, &[1, 2]);
        let sealed = seal_with(Some(&r), SECRET).expect("seal");
        assert!(
            sealed.starts_with("v2:2:"),
            "got {}",
            &sealed[..6.min(sealed.len())]
        );
        assert_eq!(envelope_key_version(&sealed), Some(2));
        assert_eq!(unseal_with(Some(&r), &sealed).expect("open"), SECRET);
    }

    #[test]
    fn v1_envelope_still_unseals_under_ring_with_key_one() {
        std::env::set_var(ALLOW_TEST_KEY_ENV, "1");
        let v1 = seal_with(None, SECRET).expect("v1 seal");
        assert!(v1.starts_with("v1:"));
        let r = TotpKeyRing::new(2, [(1, TEST_SEAL_KEY), (2, [2u8; 32])]).expect("ring");
        assert_eq!(unseal_with(Some(&r), &v1).expect("open"), SECRET);
        assert!(needs_reseal_with(Some(&r), &v1));
    }

    #[test]
    fn old_key_versions_are_retained_after_rotation() {
        let before = ring(1, &[1]);
        let sealed_old = seal_with(Some(&before), SECRET).expect("seal under v1 ring");
        let after = ring(2, &[1, 2]);
        assert_eq!(
            unseal_with(Some(&after), &sealed_old).expect("open"),
            SECRET
        );
        assert!(needs_reseal_with(Some(&after), &sealed_old));
        let resealed = seal_with(
            Some(&after),
            &unseal_with(Some(&after), &sealed_old).unwrap(),
        )
        .expect("reseal");
        assert_eq!(envelope_key_version(&resealed), Some(2));
        assert!(!needs_reseal_with(Some(&after), &resealed));
    }

    #[test]
    fn current_version_and_no_ring_envelope_do_not_need_reseal() {
        std::env::set_var(ALLOW_TEST_KEY_ENV, "1");
        let r = ring(3, &[1, 3]);
        let sealed = seal_with(Some(&r), SECRET).expect("seal");
        assert!(!needs_reseal_with(Some(&r), &sealed));
        let v1 = seal_with(None, SECRET).expect("v1");
        assert!(!needs_reseal_with(None, &v1));
        assert!(needs_reseal_with(None, SECRET), "plaintext always re-seals");
    }

    #[test]
    fn relabeled_version_fails_to_open_sad() {
        let r = ring(2, &[1, 2]);
        let sealed = seal_with(Some(&r), SECRET).expect("seal");
        let relabeled = sealed.replacen("v2:2:", "v2:1:", 1);
        let err = unseal_with(Some(&r), &relabeled).expect_err("aad/key mismatch");
        assert!(matches!(err, FactorChallengeError::TotpSecret));
    }

    #[test]
    fn unknown_version_fails_closed_and_requests_resync_sad() {
        static HITS: AtomicUsize = AtomicUsize::new(0);
        set_resync_hook(|| {
            HITS.fetch_add(1, Ordering::SeqCst);
        });
        let writer = ring(5, &[5]);
        let sealed = seal_with(Some(&writer), SECRET).expect("seal");
        let reader = ring(2, &[1, 2]);
        let before = HITS.load(Ordering::SeqCst);
        let err = unseal_with(Some(&reader), &sealed).expect_err("unknown version");
        assert!(matches!(err, FactorChallengeError::TotpSecret));
        assert_eq!(HITS.load(Ordering::SeqCst), before + 1);
        assert!(!err.to_string().contains("v2:5"));
    }

    #[test]
    fn malformed_v2_header_fails_closed_sad() {
        let r = ring(1, &[1]);
        for bad in ["v2:", "v2:abc:AAAA", "v2:1", "v2::AAAA"] {
            assert!(unseal_with(Some(&r), bad).is_err(), "{bad} must not open");
        }
    }
}
