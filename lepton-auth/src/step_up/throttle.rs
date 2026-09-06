//! Attempt throttle and lockout helpers for TOTP verify.

use chrono::{DateTime, Duration, Utc};

/// Max consecutive failures before lockout.
pub const MAX_FAILED_ATTEMPTS: i64 = 5;
/// Lockout duration after the attempt budget is exhausted.
pub const LOCKOUT_SECS: i64 = 300;

/// Whether `locked_until` is still in the future.
#[must_use]
pub fn is_locked(locked_until: Option<&DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    locked_until.is_some_and(|until| *until > now)
}

/// Next failed-attempt count and optional new lockout deadline after a miss.
#[must_use]
pub fn record_failure(failed_attempts: i64, now: DateTime<Utc>) -> (i64, Option<DateTime<Utc>>) {
    let next = failed_attempts.saturating_add(1);
    if next >= MAX_FAILED_ATTEMPTS {
        (next, Some(now + Duration::seconds(LOCKOUT_SECS)))
    } else {
        (next, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::step_up::error::StepUpError;

    #[test]
    fn lockout_after_budget() {
        let now = Utc::now();
        let (n, until) = record_failure(MAX_FAILED_ATTEMPTS - 1, now);
        assert_eq!(n, MAX_FAILED_ATTEMPTS);
        assert!(until.is_some());
        assert!(is_locked(until.as_ref(), now));
        // verify path maps lockout / budget exhaustion to this reason_class.
        assert_eq!(
            StepUpError::StepUpRateLimited.reason_class(),
            "step_up_rate_limited"
        );
    }

    #[test]
    fn no_lockout_before_budget() {
        let now = Utc::now();
        let (n, until) = record_failure(1, now);
        assert_eq!(n, 2);
        assert!(until.is_none());
        assert_eq!(StepUpError::StepUpInvalid.reason_class(), "step_up_invalid");
    }
}
