//! Extract email verification tokens and TOTP otpauth secrets.

use lepton_auth::routes::parse_token_from_url_parts;
use url::Url;

/// Parse an email verification token from a bare id, full URL, or fragment/query paste.
///
/// # Errors
///
/// Returns `None` when input is empty or no token can be extracted.
#[must_use]
pub fn email_token_from_input(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(url) = Url::parse(trimmed) {
        let search = url.query().unwrap_or("");
        let fragment = url.fragment().unwrap_or("");
        if let Some(token) = parse_token_from_url_parts(search, fragment) {
            return Some(token);
        }
    }

    // Fragment / query paste without a full URL (e.g. `token=abc` or `#token=abc`).
    if let Some(token) = parse_token_from_url_parts("", trimmed.trim_start_matches('#')) {
        return Some(token);
    }

    // Bare token id (no `=` / URL structure).
    if !trimmed.contains('=') && !trimmed.contains('/') && !trimmed.contains('?') {
        return Some(trimmed.to_string());
    }

    None
}

/// Fields for Google Authenticator-style **Enter a setup key** manual entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TotpManualEntry {
    /// Account name shown in the app (decoded; often an email).
    pub account: String,
    /// Issuer / site name (decoded), when present.
    pub issuer: String,
    /// Base32 secret (`secret=` query value).
    pub secret: String,
}

/// Extract the base32 `secret=` value from an `otpauth://` URI (authenticator QR payload).
///
/// # Errors
///
/// Returns `None` when the URI is empty, not parseable, or has no non-empty `secret`.
#[must_use]
pub fn totp_secret_from_otpauth_uri(uri: &str) -> Option<String> {
    totp_manual_entry_from_otpauth_uri(uri).map(|e| e.secret)
}

/// Parse account, issuer, and secret from an `otpauth://` URI for manual authenticator entry.
///
/// # Errors
///
/// Returns `None` when the URI is empty, not parseable, or has no non-empty `secret`.
#[must_use]
pub fn totp_manual_entry_from_otpauth_uri(uri: &str) -> Option<TotpManualEntry> {
    let trimmed = uri.trim();
    if trimmed.is_empty() {
        return None;
    }
    let url = Url::parse(trimmed).ok()?;
    let secret = url
        .query_pairs()
        .find(|(key, _)| key == "secret")
        .map(|(_, value)| value.into_owned())
        .filter(|s| !s.is_empty())?;

    let issuer_q = url
        .query_pairs()
        .find(|(key, _)| key == "issuer")
        .map_or_else(String::new, |(_, value)| value.into_owned());

    // Path is typically `totp/Issuer:account` (issuer/account may be percent-encoded).
    let path = url.path().trim_start_matches('/');
    let label = path
        .strip_prefix("totp/")
        .or_else(|| path.strip_prefix("hotp/"))
        .unwrap_or(path);
    let (issuer_path, account_enc) = match label.split_once(':') {
        Some((iss, acct)) => (iss.to_string(), acct),
        None => (String::new(), label),
    };
    let account = match urlencoding::decode(account_enc) {
        Ok(decoded) => decoded.into_owned(),
        Err(_) => account_enc.to_string(),
    };
    let issuer = if !issuer_q.is_empty() {
        issuer_q
    } else if !issuer_path.is_empty() {
        match urlencoding::decode(&issuer_path) {
            Ok(decoded) => decoded.into_owned(),
            Err(_) => issuer_path,
        }
    } else {
        String::new()
    };

    Some(TotpManualEntry {
        account,
        issuer,
        secret,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_token_happy() {
        assert_eq!(
            email_token_from_input("  abc123def456  ").as_deref(),
            Some("abc123def456")
        );
    }

    #[test]
    fn full_url_fragment_happy() {
        let input = "http://127.0.0.1:3000/user/account-settings#token=deadbeefcafe";
        assert_eq!(
            email_token_from_input(input).as_deref(),
            Some("deadbeefcafe")
        );
    }

    #[test]
    fn empty_and_garbage_sad() {
        assert!(email_token_from_input("").is_none());
        assert!(email_token_from_input("   ").is_none());
        assert!(email_token_from_input("http://example.test/no-token").is_none());
        assert!(email_token_from_input("foo=bar&baz=qux").is_none());
    }

    #[test]
    fn totp_secret_from_otpauth_uri_happy() {
        let uri = "otpauth://totp/Lepton:user?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Lepton&algorithm=SHA1&digits=6&period=30";
        assert_eq!(
            totp_secret_from_otpauth_uri(uri).as_deref(),
            Some("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        );
    }

    #[test]
    fn totp_manual_entry_from_otpauth_uri_happy() {
        let uri = "otpauth://totp/Acme%20Site:you%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Acme%20Site&algorithm=SHA1&digits=6&period=30";
        let entry = totp_manual_entry_from_otpauth_uri(uri).expect("entry");
        assert_eq!(entry.account, "you@example.com");
        assert_eq!(entry.issuer, "Acme Site");
        assert_eq!(entry.secret, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    }

    #[test]
    fn totp_secret_from_otpauth_uri_empty_and_garbage_sad() {
        assert!(totp_secret_from_otpauth_uri("").is_none());
        assert!(totp_secret_from_otpauth_uri("   ").is_none());
        assert!(totp_secret_from_otpauth_uri("not-a-uri").is_none());
        assert!(totp_secret_from_otpauth_uri("otpauth://totp/Lepton:user?issuer=Lepton").is_none());
        assert!(totp_secret_from_otpauth_uri("otpauth://totp/Lepton:user?secret=").is_none());
    }
}
