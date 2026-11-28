//! The device code a device polls with, and the user code a person types.

use std::fmt::Write;

use rand_core::{OsRng, RngCore};

use crate::tokens::hash_token_secret;

/// Fixed prefix of every device code.
pub const DEVICE_CODE_PREFIX: &str = "lpdc_";

/// Letters a user code is made of: consonants only, so a code never spells a word and has no
/// look-alike characters (RFC 8628 section 6.1).
pub const USER_CODE_ALPHABET: &[u8; 20] = b"BCDFGHJKLMNPQRSTVWXZ";

const USER_CODE_LEN: usize = 8;
const SECRET_HEX_LEN: usize = 64;

/// Why a presented device code is not shaped like one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceCodeParseError {
    /// Missing the `lpdc_` prefix or the `_` between id and secret.
    Shape,
    /// The id is not a canonical UUID.
    Id,
    /// The secret is not 64 lowercase hex characters.
    Secret,
}

/// A device code: `lpdc_<authorization id>_<secret>`.
///
/// The id names the `device_authorization` row and, once approved, the `signed_in_device`
/// row. Only a SHA-256 hash of the secret is stored.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceCode {
    id: String,
    secret: String,
}

impl std::fmt::Debug for DeviceCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceCode")
            .field("id", &self.id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl DeviceCode {
    /// A fresh code with a random id and a random 256-bit secret.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            secret: bytes.iter().fold(String::with_capacity(64), |mut hex, b| {
                let _ = write!(hex, "{b:02x}");
                hex
            }),
        }
    }

    /// Parse `lpdc_<id>_<secret>`.
    ///
    /// # Errors
    ///
    /// [`DeviceCodeParseError`] naming the first part that is wrong.
    pub fn parse(raw: &str) -> Result<Self, DeviceCodeParseError> {
        let rest = raw
            .trim()
            .strip_prefix(DEVICE_CODE_PREFIX)
            .ok_or(DeviceCodeParseError::Shape)?;
        let (id, secret) = rest.split_once('_').ok_or(DeviceCodeParseError::Shape)?;
        let parsed = uuid::Uuid::parse_str(id).map_err(|_| DeviceCodeParseError::Id)?;
        if parsed.to_string() != id {
            return Err(DeviceCodeParseError::Id);
        }
        let hex_ok = secret.len() == SECRET_HEX_LEN
            && secret
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !hex_ok {
            return Err(DeviceCodeParseError::Secret);
        }
        Ok(Self {
            id: id.to_string(),
            secret: secret.to_string(),
        })
    }

    /// The authorization (and device record) id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The value stored in `device_code_hash`.
    #[must_use]
    pub fn hash(&self) -> String {
        hash_token_secret(&self.secret)
    }

    /// Whether `stored` is this code's hash, compared in constant time.
    #[must_use]
    pub fn matches(&self, stored: &str) -> bool {
        crate::tokens::constant_time_eq(stored, &self.hash())
    }

    /// The full code to hand to the device. It cannot be recovered later.
    #[must_use]
    pub fn expose(&self) -> String {
        format!("{DEVICE_CODE_PREFIX}{}_{}", self.id, self.secret)
    }

    /// A fresh user code, `XXXX-XXXX` from [`USER_CODE_ALPHABET`].
    #[must_use]
    pub fn generate_user_code() -> String {
        let mut letters = Vec::with_capacity(USER_CODE_LEN);
        let mut byte = [0u8; 1];
        while letters.len() < USER_CODE_LEN {
            OsRng.fill_bytes(&mut byte);
            // 240 is the largest multiple of 20 below 256; rejecting the rest keeps every
            // letter equally likely.
            if byte[0] < 240 {
                letters.push(USER_CODE_ALPHABET[usize::from(byte[0] % 20)]);
            }
        }
        format_user_code(&letters)
    }
}

fn format_user_code(letters: &[u8]) -> String {
    let (a, b) = letters.split_at(USER_CODE_LEN / 2);
    format!(
        "{}-{}",
        String::from_utf8_lossy(a),
        String::from_utf8_lossy(b)
    )
}

/// The stored form of a typed user code, or `None` when it can't be one.
///
/// Case, spaces and dashes don't matter, so `wdjb mjht` and `WDJB-MJHT` both give
/// `WDJB-MJHT`.
#[must_use]
pub fn normalize_user_code(raw: &str) -> Option<String> {
    let letters: Vec<u8> = raw
        .bytes()
        .filter(|b| !matches!(b, b'-' | b' '))
        .map(|b| b.to_ascii_uppercase())
        .collect();
    let valid =
        letters.len() == USER_CODE_LEN && letters.iter().all(|b| USER_CODE_ALPHABET.contains(b));
    valid.then(|| format_user_code(&letters))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_code_round_trips_happy() {
        let code = DeviceCode::generate();
        let parsed = DeviceCode::parse(&code.expose()).expect("parses");
        assert_eq!(parsed, code);
        assert!(parsed.matches(&code.hash()));
        assert!(!format!("{code:?}").contains(&code.secret));
    }

    #[test]
    fn device_code_bad_shapes_sad() {
        let code = DeviceCode::generate().expose();
        assert_eq!(
            DeviceCode::parse(&code.replacen("lpdc_", "lptk_", 1)),
            Err(DeviceCodeParseError::Shape)
        );
        assert_eq!(
            DeviceCode::parse("lpdc_not-a-uuid_00"),
            Err(DeviceCodeParseError::Id)
        );
        assert_eq!(
            DeviceCode::parse(&format!("{}x", &code[..code.len() - 1])),
            Err(DeviceCodeParseError::Secret)
        );
        let other = DeviceCode::generate();
        assert!(!DeviceCode::parse(&code)
            .expect("parses")
            .matches(&other.hash()));
    }

    #[test]
    fn user_code_shape_happy() {
        for _ in 0..50 {
            let code = DeviceCode::generate_user_code();
            assert_eq!(code.len(), 9);
            assert_eq!(code.as_bytes()[4], b'-');
            assert_eq!(normalize_user_code(&code).as_deref(), Some(code.as_str()));
        }
    }

    #[test]
    fn normalize_user_code_cases() {
        assert_eq!(
            normalize_user_code("wdjb mjht").as_deref(),
            Some("WDJB-MJHT")
        );
        assert_eq!(
            normalize_user_code("WDJBMJHT").as_deref(),
            Some("WDJB-MJHT")
        );
        assert_eq!(normalize_user_code("WDJB-MJH"), None);
        assert_eq!(
            normalize_user_code("WDJB-MJHA"),
            None,
            "vowels are never issued"
        );
        assert_eq!(normalize_user_code(""), None);
    }
}
