//! Service user handles: validation, clash keys, and suggestions.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Shortest allowed handle, in characters.
pub const MIN_HANDLE_LEN: usize = 3;
/// Longest allowed handle, in characters.
pub const MAX_HANDLE_LEN: usize = 32;

const MAX_SUGGESTIONS: u32 = 99;

/// Clash keys (dashes removed) that would let a service user pass for staff,
/// the platform, everyone, or the `svc:` actor prefix.
const RESERVED_STEMS: &[&str] = &[
    "",
    "admin",
    "administrator",
    "all",
    "everyone",
    "gauge",
    "help",
    "lepton",
    "mod",
    "moderator",
    "official",
    "owner",
    "root",
    "security",
    "service",
    "staff",
    "superuser",
    "support",
    "svc",
    "system",
    "team",
    "uf",
    "unifiedfield",
];

/// A validated service user handle such as `spectra-agent`.
///
/// Handles are 3–32 characters of `a-z`, `0-9` and single dashes, and start
/// and end with a letter or digit. They live in their own namespace: people have no
/// handles, and two service users can never hold handles with the same
/// [`key`](Self::key). The service rejects a handle whose key is taken, but the
/// service user's identity is its [`ServiceUserId`](super::ServiceUserId).
/// Screens show a handle as `@handle` next to a "Service user" badge, so it is
/// not read as a person's name.
///
/// # Examples
///
/// ```
/// use lepton_identity::service_users::{ServiceUserHandle, ServiceUserHandleError};
///
/// let handle = ServiceUserHandle::parse("Spectra-Agent").expect("valid");
/// assert_eq!(handle.as_str(), "spectra-agent");
/// assert_eq!(handle.key(), "spectraagent");
///
/// assert_eq!(ServiceUserHandle::parse("support"), Err(ServiceUserHandleError::Reserved));
/// assert_eq!(ServiceUserHandle::parse("s-v-c"), Err(ServiceUserHandleError::Reserved));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServiceUserHandle(String);

/// Why a handle was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceUserHandleError {
    /// Fewer than [`MIN_HANDLE_LEN`] characters.
    TooShort,
    /// More than [`MAX_HANDLE_LEN`] characters.
    TooLong,
    /// A character outside `a-z`, `0-9`, `-`, or a leading, trailing, or doubled dash.
    InvalidChar,
    /// The handle names staff, the platform, or everyone.
    Reserved,
}

impl ServiceUserHandleError {
    /// Stable, loggable sub-reason.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::TooShort => "too_short",
            Self::TooLong => "too_long",
            Self::InvalidChar => "invalid_char",
            Self::Reserved => "reserved",
        }
    }
}

impl fmt::Display for ServiceUserHandleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "reason_class=handle: {}", self.reason())
    }
}

impl std::error::Error for ServiceUserHandleError {}

impl ServiceUserHandle {
    /// Validate a handle. Uppercase ASCII is folded to lowercase; nothing else
    /// is rewritten.
    ///
    /// # Errors
    ///
    /// A [`ServiceUserHandleError`] naming the first rule the text breaks.
    pub fn parse(text: &str) -> Result<Self, ServiceUserHandleError> {
        let handle = text.to_ascii_lowercase();
        let len = handle.chars().count();
        if len < MIN_HANDLE_LEN {
            return Err(ServiceUserHandleError::TooShort);
        }
        if len > MAX_HANDLE_LEN {
            return Err(ServiceUserHandleError::TooLong);
        }
        let valid_chars = handle
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if !valid_chars || handle.starts_with('-') || handle.ends_with('-') || handle.contains("--")
        {
            return Err(ServiceUserHandleError::InvalidChar);
        }
        let candidate = Self(handle);
        if RESERVED_STEMS.contains(&candidate.key().as_str()) {
            return Err(ServiceUserHandleError::Reserved);
        }
        Ok(candidate)
    }

    /// Turn free text (for example a display name) into a valid handle:
    /// lowercase, with spaces and punctuation turned into single dashes.
    ///
    /// # Errors
    ///
    /// [`ServiceUserHandleError::Reserved`] or [`ServiceUserHandleError::TooShort`] when nothing
    /// usable is left after normalizing.
    pub fn normalize(text: &str) -> Result<Self, ServiceUserHandleError> {
        let mut slug = String::with_capacity(text.len());
        for c in text.chars() {
            let c = c.to_ascii_lowercase();
            if c.is_ascii_lowercase() || c.is_ascii_digit() {
                slug.push(c);
            } else if !slug.is_empty() && !slug.ends_with('-') {
                slug.push('-');
            }
        }
        Self::parse(&fit(slug.trim_end_matches('-'), None))
    }

    /// The handle text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The clash key: the handle with dashes removed, so `spectra-agent` and
    /// `spectraagent` collide.
    #[must_use]
    pub fn key(&self) -> String {
        self.0.replace('-', "")
    }

    /// Up to 98 alternatives in order: `spectra-agent-2`, `spectra-agent-3`, …
    /// Every candidate is a valid handle.
    pub fn suggestions(&self) -> impl Iterator<Item = Self> + '_ {
        (2..=MAX_SUGGESTIONS).filter_map(move |n| Self::parse(&fit(&self.0, Some(n))).ok())
    }
}

impl Serialize for ServiceUserHandle {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

/// Deserializes through [`ServiceUserHandle::parse`], so the handle rules hold for
/// values that arrive over the wire.
impl<'de> Deserialize<'de> for ServiceUserHandle {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for ServiceUserHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Build `<stem>[-<n>]`, trimming the stem so the result fits.
fn fit(stem: &str, n: Option<u32>) -> String {
    let tail = n.map_or_else(String::new, |n| format!("-{n}"));
    let room = MAX_HANDLE_LEN.saturating_sub(tail.len());
    let stem: String = stem.chars().take(room).collect();
    let stem = stem.trim_end_matches('-');
    format!("{stem}{tail}")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn handle_parse_ok_happy() {
        for ok in ["spectra-agent", "abc", "r2d2", "magnon-reader", "ci-7"] {
            let h = ServiceUserHandle::parse(ok).expect(ok);
            assert_eq!(h.as_str(), ok);
        }
        assert_eq!(
            ServiceUserHandle::parse("Spectra-AGENT")
                .expect("folds")
                .as_str(),
            "spectra-agent"
        );
        let longest = "a".repeat(MAX_HANDLE_LEN);
        assert_eq!(
            ServiceUserHandle::parse(&longest).expect("32").as_str(),
            longest
        );
    }

    #[test]
    fn handle_parse_without_suffix_happy() {
        // Handles no longer need a `bot` suffix; names that used to be refused parse.
        for ok in ["sean", "spectra", "robots", "service-user-sean"] {
            assert_eq!(ServiceUserHandle::parse(ok).expect(ok).as_str(), ok);
        }
    }

    #[test]
    fn handle_parse_legacy_bot_suffix_still_valid_happy() {
        for ok in ["spectra-bot", "abot", "r2d2bot", "magnon-reader-bot"] {
            assert_eq!(ServiceUserHandle::parse(ok).expect(ok).as_str(), ok);
        }
    }

    #[test]
    fn handle_parse_too_short_sad() {
        assert_eq!(
            ServiceUserHandle::parse("bo"),
            Err(ServiceUserHandleError::TooShort)
        );
        assert_eq!(
            ServiceUserHandle::parse(""),
            Err(ServiceUserHandleError::TooShort)
        );
    }

    #[test]
    fn handle_parse_too_long_sad() {
        let long = "a".repeat(MAX_HANDLE_LEN + 1);
        assert_eq!(
            ServiceUserHandle::parse(&long),
            Err(ServiceUserHandleError::TooLong)
        );
    }

    #[test]
    fn handle_parse_bad_char_sad() {
        for bad in [
            "spectra_agent",
            "spec tra",
            "-spectra",
            "spectra-",
            "spectra-agent-",
            "spectra--agent",
            "spéctra",
            "@spectra",
        ] {
            assert_eq!(
                ServiceUserHandle::parse(bad),
                Err(ServiceUserHandleError::InvalidChar),
                "{bad}"
            );
        }
    }

    #[test]
    fn handle_parse_reserved_sad() {
        for bad in [
            "admin",
            "a-d-m-i-n",
            "support",
            "system",
            "unified-field",
            "everyone",
        ] {
            assert_eq!(
                ServiceUserHandle::parse(bad),
                Err(ServiceUserHandleError::Reserved),
                "{bad}"
            );
        }
    }

    #[test]
    fn handle_parse_reserved_svc_stems_sad() {
        for bad in ["svc", "s-v-c", "service", "Service", "ser-vice"] {
            assert_eq!(
                ServiceUserHandle::parse(bad),
                Err(ServiceUserHandleError::Reserved),
                "{bad}"
            );
        }
    }

    #[test]
    fn handle_serde_round_trip_happy() {
        let h = ServiceUserHandle::parse("spectra-agent").expect("h");
        let json = serde_json::to_string(&h).expect("serialize");
        assert_eq!(json, "\"spectra-agent\"");
        let back: ServiceUserHandle = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, h);
        let folded: ServiceUserHandle = serde_json::from_str("\"Spectra-Agent\"").expect("folds");
        assert_eq!(folded, h);
    }

    #[test]
    fn handle_serde_rejects_invalid_sad() {
        for bad in ["\"handle-\"", "\"admin\"", "\"ab\"", "\"a_b_c\"", "7"] {
            assert!(
                serde_json::from_str::<ServiceUserHandle>(bad).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn handle_key_folds_case_and_dashes_happy() {
        let a = ServiceUserHandle::parse("Spectra-Agent").expect("a");
        let b = ServiceUserHandle::parse("spectraagent").expect("b");
        assert_eq!(a.key(), "spectraagent");
        assert_eq!(a.key(), b.key());
        assert_ne!(a, b);
    }

    #[test]
    fn suggest_candidates_order_happy() {
        let h = ServiceUserHandle::parse("spectra").expect("h");
        let first: Vec<String> = h
            .suggestions()
            .take(3)
            .map(|s| s.as_str().to_string())
            .collect();
        assert_eq!(first, ["spectra-2", "spectra-3", "spectra-4"]);
        assert_eq!(h.suggestions().count(), 98);

        let long = ServiceUserHandle::parse(&"a".repeat(MAX_HANDLE_LEN)).expect("long");
        for s in long.suggestions() {
            assert!(s.as_str().len() <= MAX_HANDLE_LEN, "{s}");
        }
    }

    #[test]
    fn normalize_free_text_happy() {
        assert_eq!(
            ServiceUserHandle::normalize("Spectra agent")
                .expect("n")
                .as_str(),
            "spectra-agent"
        );
        assert_eq!(
            ServiceUserHandle::normalize("Metrics agent!")
                .expect("n")
                .as_str(),
            "metrics-agent"
        );
        assert_eq!(
            ServiceUserHandle::normalize("r2d2").expect("n").as_str(),
            "r2d2"
        );
    }

    #[test]
    fn normalize_nothing_usable_sad() {
        assert_eq!(
            ServiceUserHandle::normalize("!!!"),
            Err(ServiceUserHandleError::TooShort)
        );
        assert_eq!(
            ServiceUserHandle::normalize("Support"),
            Err(ServiceUserHandleError::Reserved)
        );
    }
}
