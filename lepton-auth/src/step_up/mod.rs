//! Session-bound TOTP step-up (sudo window) for sensitive mutations.
//!
//! Hosts call [`verify_totp_for_session`] from a dedicated server function, then
//! gated mutations call [`require_recent_verification`]. Use
//! [`verify_fresh_totp`] when a single call must present a code even if a window
//! is open (break-glass reveal, Super User membership, handoff finalize).

mod error;
mod scope;
mod throttle;
mod verify;
mod window;

pub use crate::session_binding::STEP_UP_TTL_SECS;
pub use error::StepUpError;
pub use scope::{StepUpMode, StepUpScope};
pub use verify::{
    require_recent_verification, verify_code_against_factor, verify_fresh_totp,
    verify_fresh_totp_for_session_user, verify_totp_for_session, StepUpOutcome,
};
pub use window::{clear_window, load_window, window_matches_identity, LoadedWindow};
