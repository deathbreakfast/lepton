//! Operation class and verify mode for step-up.

/// Logical class recorded on the session window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepUpScope {
    /// Default sensitive mutation window (Gauge / Gluon / Neutrino Tier A).
    SensitiveMutation,
}

impl StepUpScope {
    /// Stable string stored in the session bag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SensitiveMutation => "sensitive_mutation",
        }
    }

    /// Parse a stored scope string.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "sensitive_mutation" => Some(Self::SensitiveMutation),
            _ => None,
        }
    }
}

/// How a gated server function consumes step-up proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepUpMode {
    /// Accept an unexpired session window.
    Window,
    /// Demand a fresh TOTP for this call; ignore any open window.
    Fresh,
}

impl StepUpMode {
    /// Macro / attribute token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Window => "window",
            Self::Fresh => "fresh",
        }
    }

    /// Parse a macro attribute token (`window` / `fresh` / empty → window).
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "" | "window" | "true" => Some(Self::Window),
            "fresh" => Some(Self::Fresh),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_roundtrip() {
        assert_eq!(
            StepUpScope::parse(StepUpScope::SensitiveMutation.as_str()),
            Some(StepUpScope::SensitiveMutation)
        );
        assert_eq!(StepUpScope::parse("other"), None);
    }

    #[test]
    fn mode_parse_window_and_fresh() {
        assert_eq!(StepUpMode::parse(""), Some(StepUpMode::Window));
        assert_eq!(StepUpMode::parse("window"), Some(StepUpMode::Window));
        assert_eq!(StepUpMode::parse("fresh"), Some(StepUpMode::Fresh));
        assert_eq!(StepUpMode::parse("bogus"), None);
    }
}
