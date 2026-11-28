//! The bearer string every Lepton token shares: `lptk_<token id>_<secret>`.

use sha2::{Digest, Sha256};

/// Fixed prefix of every Lepton token, so scanners and logs can spot a leaked one.
///
/// Lepton's bearer path accepts nothing else. The older `lpt_` service user tokens no longer
/// verify, and a host's own token formats (FamBam's `fbtk_`) never reach Lepton.
pub const TOKEN_PREFIX: &str = "lptk_";

const SECRET_HEX_LEN: usize = 64;

/// Why a presented token string is not shaped like a Lepton token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenParseError {
    /// Missing the `lptk_` prefix or the `_` between id and secret.
    Shape,
    /// The token id is not a canonical UUID.
    Id,
    /// The secret is not 64 lowercase hex characters.
    Secret,
}

/// A parsed token: the row id and the secret half.
///
/// The row id names a `personal_token` or a `service_user_token` row. Both tables use random
/// UUIDs, so one id never names rows in both.
#[derive(Clone, PartialEq, Eq)]
pub struct LeptonToken {
    id: String,
    secret: String,
}

impl std::fmt::Debug for LeptonToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeptonToken")
            .field("id", &self.id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl LeptonToken {
    /// A fresh token with a random id and a random 256-bit secret.
    #[must_use]
    pub fn generate() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            secret: to_hex(&bytes),
        }
    }

    /// Parse `lptk_<id>_<secret>`.
    ///
    /// # Errors
    ///
    /// [`TokenParseError`] naming the first part that is wrong.
    pub fn parse(raw: &str) -> Result<Self, TokenParseError> {
        let rest = raw
            .strip_prefix(TOKEN_PREFIX)
            .ok_or(TokenParseError::Shape)?;
        let (id, secret) = rest.split_once('_').ok_or(TokenParseError::Shape)?;
        let parsed = uuid::Uuid::parse_str(id).map_err(|_| TokenParseError::Id)?;
        if parsed.to_string() != id {
            return Err(TokenParseError::Id);
        }
        let hex_ok = secret.len() == SECRET_HEX_LEN
            && secret
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !hex_ok {
            return Err(TokenParseError::Secret);
        }
        Ok(Self {
            id: id.to_string(),
            secret: secret.to_string(),
        })
    }

    /// The token's row key.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The value to store in `token_hash`.
    #[must_use]
    pub fn hash(&self) -> String {
        hash_token_secret(&self.secret)
    }

    /// The full token string. Show it to the owner once; it cannot be recovered later.
    #[must_use]
    pub fn expose(&self) -> String {
        format!("{TOKEN_PREFIX}{}_{}", self.id, self.secret)
    }
}

/// Lowercase hex SHA-256 of a token secret.
#[must_use]
pub fn hash_token_secret(secret: &str) -> String {
    to_hex(&Sha256::digest(secret.as_bytes()))
}

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

pub(super) fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_parse_roundtrip_happy() {
        let token = LeptonToken::generate();
        let exposed = token.expose();
        assert!(exposed.starts_with("lptk_"));
        let parsed = LeptonToken::parse(&exposed).expect("parse");
        assert_eq!(parsed, token);
        assert_eq!(parsed.hash(), token.hash());
        assert_eq!(token.hash().len(), 64);
        assert_ne!(token.hash(), token.secret);
    }

    #[test]
    fn parse_rejects_malformed_sad() {
        let good = LeptonToken::generate().expose();
        for bad in [
            "",
            "lptk_",
            "nope",
            &good.replacen("lptk_", "xptk_", 1),
            // The retired service user prefix.
            &good.replacen("lptk_", "lpt_", 1),
            &good.replacen("lptk_", "fbtk_", 1),
            &good[..good.len() - 1],
            &format!("{good}0"),
            &good.to_uppercase(),
            "lptk_not-a-uuid_00",
        ] {
            assert!(LeptonToken::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn debug_redacts_secret_sad() {
        let token = LeptonToken::generate();
        assert!(!format!("{token:?}").contains(&token.secret));
    }

    #[test]
    fn constant_time_eq_cases() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
    }
}
