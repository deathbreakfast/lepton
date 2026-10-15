//! Bot handles: validation, clash keys, and suggestions.

use std::fmt;

/// Shortest allowed handle, in characters.
pub const MIN_HANDLE_LEN: usize = 3;
/// Longest allowed handle, in characters.
pub const MAX_HANDLE_LEN: usize = 32;

const SUFFIX: &str = "bot";
const MAX_SUGGESTIONS: u32 = 99;

/// Clash keys (dashes removed, `bot` suffix removed) that would let a bot pass
/// for staff, the platform, or everyone.
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
    "staff",
    "superuser",
    "support",
    "system",
    "team",
    "uf",
    "unifiedfield",
];

/// A validated bot handle such as `spectra-bot`.
///
/// Handles are 3–32 characters of `a-z`, `0-9` and single dashes, start with a
/// letter or digit, and end in `bot`, so a bot cannot pass for a person by its
/// handle alone. Handles are pseudo-unique: the service rejects one whose
/// [`key`](Self::key) is already taken, but the bot's identity is its
/// [`BotId`](super::BotId).
///
/// # Examples
///
/// ```
/// use lepton_identity::bots::{BotHandle, BotHandleError};
///
/// let handle = BotHandle::parse("Spectra-Bot").expect("valid");
/// assert_eq!(handle.as_str(), "spectra-bot");
/// assert_eq!(handle.key(), "spectrabot");
///
/// assert_eq!(BotHandle::parse("sean"), Err(BotHandleError::MissingBotSuffix));
/// assert_eq!(BotHandle::parse("support-bot"), Err(BotHandleError::Reserved));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BotHandle(String);

/// Why a handle was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BotHandleError {
    /// Fewer than [`MIN_HANDLE_LEN`] characters.
    TooShort,
    /// More than [`MAX_HANDLE_LEN`] characters.
    TooLong,
    /// A character outside `a-z`, `0-9`, `-`, or a leading or doubled dash.
    InvalidChar,
    /// The handle does not end in `bot`.
    MissingBotSuffix,
    /// The handle names staff, the platform, or everyone.
    Reserved,
}

impl BotHandleError {
    /// Stable, loggable sub-reason.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::TooShort => "too_short",
            Self::TooLong => "too_long",
            Self::InvalidChar => "invalid_char",
            Self::MissingBotSuffix => "missing_bot_suffix",
            Self::Reserved => "reserved",
        }
    }
}

impl fmt::Display for BotHandleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "reason_class=handle: {}", self.reason())
    }
}

impl std::error::Error for BotHandleError {}

impl BotHandle {
    /// Validate a handle. Uppercase ASCII is folded to lowercase; nothing else
    /// is rewritten.
    ///
    /// # Errors
    ///
    /// A [`BotHandleError`] naming the first rule the text breaks.
    pub fn parse(text: &str) -> Result<Self, BotHandleError> {
        let handle = text.to_ascii_lowercase();
        let len = handle.chars().count();
        if len < MIN_HANDLE_LEN {
            return Err(BotHandleError::TooShort);
        }
        if len > MAX_HANDLE_LEN {
            return Err(BotHandleError::TooLong);
        }
        let valid_chars = handle
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if !valid_chars || handle.starts_with('-') || handle.contains("--") {
            return Err(BotHandleError::InvalidChar);
        }
        if !handle.ends_with(SUFFIX) {
            return Err(BotHandleError::MissingBotSuffix);
        }
        let candidate = Self(handle);
        if RESERVED_STEMS.contains(&candidate.stem_key().as_str()) {
            return Err(BotHandleError::Reserved);
        }
        Ok(candidate)
    }

    /// Turn free text (for example a display name) into a valid handle:
    /// lowercase, spaces and punctuation become dashes, and `-bot` is appended
    /// when missing.
    ///
    /// # Errors
    ///
    /// [`BotHandleError::Reserved`] or [`BotHandleError::TooShort`] when nothing
    /// usable is left after normalizing.
    pub fn normalize(text: &str) -> Result<Self, BotHandleError> {
        let mut slug = String::with_capacity(text.len());
        for c in text.chars() {
            let c = c.to_ascii_lowercase();
            if c.is_ascii_lowercase() || c.is_ascii_digit() {
                slug.push(c);
            } else if !slug.is_empty() && !slug.ends_with('-') {
                slug.push('-');
            }
        }
        let stem = slug.trim_end_matches('-');
        let stem = stem.strip_suffix(SUFFIX).unwrap_or(stem);
        Self::parse(&with_suffix(stem.trim_end_matches('-'), None))
    }

    /// The handle text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The clash key: the handle with dashes removed, so `spectra-bot` and
    /// `spectrabot` collide.
    #[must_use]
    pub fn key(&self) -> String {
        self.0.replace('-', "")
    }

    /// Up to 98 alternatives in order: `spectra-2-bot`, `spectra-3-bot`, …
    /// Every candidate is a valid handle.
    pub fn suggestions(&self) -> impl Iterator<Item = Self> + '_ {
        let stem = self.stem();
        (2..=MAX_SUGGESTIONS).filter_map(move |n| Self::parse(&with_suffix(stem, Some(n))).ok())
    }

    fn stem(&self) -> &str {
        let stem = self.0.strip_suffix(SUFFIX).unwrap_or(&self.0);
        stem.trim_end_matches('-')
    }

    fn stem_key(&self) -> String {
        self.stem().replace('-', "")
    }
}

impl fmt::Display for BotHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Build `<stem>[-<n>]-bot`, trimming the stem so the result fits.
fn with_suffix(stem: &str, n: Option<u32>) -> String {
    let tail = n.map_or_else(|| format!("-{SUFFIX}"), |n| format!("-{n}-{SUFFIX}"));
    let room = MAX_HANDLE_LEN.saturating_sub(tail.len());
    let stem: String = stem.chars().take(room).collect();
    let stem = stem.trim_end_matches('-');
    if stem.is_empty() {
        SUFFIX.to_string()
    } else {
        format!("{stem}{tail}")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn handle_parse_ok_happy() {
        for ok in [
            "spectra-bot",
            "abot",
            "r2d2bot",
            "magnon-reader-bot",
            "x-bot",
        ] {
            let h = BotHandle::parse(ok).expect(ok);
            assert_eq!(h.as_str(), ok);
        }
        assert_eq!(
            BotHandle::parse("Spectra-BOT").expect("folds").as_str(),
            "spectra-bot"
        );
        let longest = format!("{}bot", "a".repeat(MAX_HANDLE_LEN - 3));
        assert_eq!(BotHandle::parse(&longest).expect("32").as_str(), longest);
    }

    #[test]
    fn handle_parse_too_short_sad() {
        assert_eq!(BotHandle::parse("bo"), Err(BotHandleError::TooShort));
        assert_eq!(BotHandle::parse(""), Err(BotHandleError::TooShort));
    }

    #[test]
    fn handle_parse_too_long_sad() {
        let long = format!("{}bot", "a".repeat(MAX_HANDLE_LEN - 2));
        assert_eq!(BotHandle::parse(&long), Err(BotHandleError::TooLong));
    }

    #[test]
    fn handle_parse_bad_char_sad() {
        for bad in [
            "spectra_bot",
            "spec tra-bot",
            "-spectra-bot",
            "spectra--bot",
            "spéctra-bot",
            "@spectra-bot",
        ] {
            assert_eq!(
                BotHandle::parse(bad),
                Err(BotHandleError::InvalidChar),
                "{bad}"
            );
        }
    }

    #[test]
    fn handle_parse_no_bot_suffix_sad() {
        for bad in ["sean", "spectra", "robots", "bot-sean"] {
            assert_eq!(
                BotHandle::parse(bad),
                Err(BotHandleError::MissingBotSuffix),
                "{bad}"
            );
        }
    }

    #[test]
    fn handle_parse_reserved_sad() {
        for bad in [
            "bot",
            "admin-bot",
            "adminbot",
            "support-bot",
            "system-bot",
            "unified-field-bot",
            "-bot",
        ] {
            let got = BotHandle::parse(bad);
            assert!(
                got == Err(BotHandleError::Reserved) || got == Err(BotHandleError::InvalidChar),
                "{bad}: {got:?}"
            );
        }
        assert_eq!(BotHandle::parse("admin-bot"), Err(BotHandleError::Reserved));
        assert_eq!(BotHandle::parse("bot"), Err(BotHandleError::Reserved));
    }

    #[test]
    fn handle_key_folds_case_and_dashes_happy() {
        let a = BotHandle::parse("Spectra-Bot").expect("a");
        let b = BotHandle::parse("spectrabot").expect("b");
        assert_eq!(a.key(), "spectrabot");
        assert_eq!(a.key(), b.key());
        assert_ne!(a, b);
    }

    #[test]
    fn suggest_candidates_order_happy() {
        let h = BotHandle::parse("spectra-bot").expect("h");
        let first: Vec<String> = h
            .suggestions()
            .take(3)
            .map(|s| s.as_str().to_string())
            .collect();
        assert_eq!(first, ["spectra-2-bot", "spectra-3-bot", "spectra-4-bot"]);
        assert_eq!(h.suggestions().count(), 98);

        let long =
            BotHandle::parse(&format!("{}bot", "a".repeat(MAX_HANDLE_LEN - 3))).expect("long");
        for s in long.suggestions() {
            assert!(s.as_str().len() <= MAX_HANDLE_LEN, "{s}");
        }
    }

    #[test]
    fn normalize_free_text_happy() {
        assert_eq!(
            BotHandle::normalize("Spectra Bot").expect("n").as_str(),
            "spectra-bot"
        );
        assert_eq!(
            BotHandle::normalize("Metrics agent!").expect("n").as_str(),
            "metrics-agent-bot"
        );
        assert_eq!(
            BotHandle::normalize("r2d2").expect("n").as_str(),
            "r2d2-bot"
        );
    }

    #[test]
    fn normalize_nothing_usable_sad() {
        assert_eq!(BotHandle::normalize("!!!"), Err(BotHandleError::Reserved));
        assert_eq!(
            BotHandle::normalize("Support"),
            Err(BotHandleError::Reserved)
        );
    }
}
