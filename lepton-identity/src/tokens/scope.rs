//! API scopes and token lifetimes.

use chrono::{DateTime, Duration, Utc};
use serde_json::Value;

/// Longest scope string, `api` and `action` together.
pub const MAX_SCOPE_LEN: usize = 64;

/// One API a token may call, written `<api>:<action>`, such as `magnon:read`.
///
/// Both halves are lowercase ASCII letters, digits and dashes and start with a letter. A
/// scope only opens the door to an API: the person's or service user's own permissions still
/// decide what the call may do.
///
/// ```
/// use lepton_identity::tokens::ApiScope;
///
/// let scope = ApiScope::parse("magnon:read").unwrap();
/// assert_eq!(scope.api(), "magnon");
/// assert!(ApiScope::parse("Magnon:Read").is_err());
/// assert!(ApiScope::parse("magnon").is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ApiScope(String);

/// A string that is not a valid [`ApiScope`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidApiScope;

impl std::fmt::Display for InvalidApiScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("scope must look like `api:action` in lowercase letters, digits and dashes")
    }
}

impl std::error::Error for InvalidApiScope {}

fn valid_part(part: &str) -> bool {
    part.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && part
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl ApiScope {
    /// Check and wrap a scope string.
    ///
    /// # Errors
    ///
    /// [`InvalidApiScope`] when it is not `<api>:<action>` as described on [`ApiScope`], or is
    /// longer than [`MAX_SCOPE_LEN`].
    pub fn parse(raw: &str) -> Result<Self, InvalidApiScope> {
        let (api, action) = raw.split_once(':').ok_or(InvalidApiScope)?;
        if raw.len() > MAX_SCOPE_LEN || !valid_part(api) || !valid_part(action) {
            return Err(InvalidApiScope);
        }
        Ok(Self(raw.to_string()))
    }

    /// The scope string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The API half, such as `magnon` in `magnon:read`.
    #[must_use]
    pub fn api(&self) -> &str {
        self.0
            .split_once(':')
            .map_or(self.0.as_str(), |(api, _)| api)
    }
}

impl std::fmt::Display for ApiScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The stored form of a token's scopes: a JSON array of scope strings.
#[must_use]
pub fn scopes_to_json(scopes: &[ApiScope]) -> Value {
    Value::Array(scopes.iter().map(|s| Value::String(s.0.clone())).collect())
}

/// Read stored scopes. Entries that are not valid scopes are dropped, so a damaged row can
/// only lose access, never gain it.
#[must_use]
pub fn scopes_from_json(value: Option<&Value>) -> Vec<ApiScope> {
    value.and_then(Value::as_array).map_or_default(|items| {
        items
            .iter()
            .filter_map(|v| ApiScope::parse(v.as_str()?).ok())
            .collect()
    })
}

/// How long a new token lasts: 30 or 90 days.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenLifetime {
    /// 30 days.
    Days30,
    /// 90 days.
    Days90,
}

impl TokenLifetime {
    /// Length in days.
    #[must_use]
    pub const fn days(self) -> i64 {
        match self {
            Self::Days30 => 30,
            Self::Days90 => 90,
        }
    }

    /// When a token created at `now` stops working.
    #[must_use]
    pub fn expires_at(self, now: DateTime<Utc>) -> DateTime<Utc> {
        now + Duration::days(self.days())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn scope_parse_happy() {
        for raw in [
            "magnon:read",
            "magnon:write",
            "spectra:read",
            "files:read",
            "a1-b:c-2",
        ] {
            assert_eq!(ApiScope::parse(raw).expect(raw).as_str(), raw);
        }
        assert_eq!(ApiScope::parse("files:read").expect("scope").api(), "files");
    }

    #[test]
    fn scope_parse_sad() {
        let long = format!("{}:read", "a".repeat(MAX_SCOPE_LEN));
        for raw in [
            "",
            ":",
            "magnon",
            "magnon:",
            ":read",
            "Magnon:read",
            "magnon:Read",
            "magnon:read:x",
            "1magnon:read",
            "magnon:-read",
            "magnon read",
            "magnon:read ",
            "mag_non:read",
            &long,
        ] {
            assert!(ApiScope::parse(raw).is_err(), "{raw}");
        }
    }

    #[test]
    fn scopes_json_roundtrip_drops_junk() {
        let scopes = vec![
            ApiScope::parse("magnon:read").expect("scope"),
            ApiScope::parse("files:read").expect("scope"),
        ];
        assert_eq!(scopes_from_json(Some(&scopes_to_json(&scopes))), scopes);
        let damaged = json!(["magnon:read", 7, "NOPE", null]);
        assert_eq!(scopes_from_json(Some(&damaged)), scopes[..1]);
        assert!(scopes_from_json(Some(&json!("magnon:read"))).is_empty());
        assert!(scopes_from_json(None).is_empty());
    }

    #[test]
    fn lifetime_days() {
        let now = Utc::now();
        assert_eq!(
            TokenLifetime::Days30.expires_at(now) - now,
            Duration::days(30)
        );
        assert_eq!(
            TokenLifetime::Days90.expires_at(now) - now,
            Duration::days(90)
        );
    }
}
