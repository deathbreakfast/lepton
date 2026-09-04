//! Compile/run sketch for TOTP sudo-window symbols (`ssr` + `totp`).
//!
//! Primary path teaching lives on the `lepton-auth` crate root under
//! "Verify TOTP for a sudo window". This binary only proves the public symbols
//! resolve under the feature set hosts use for step-up.
//!
//! ```bash
//! CARGO_BUILD_JOBS=1 cargo check -p lepton-auth --example step_up_totp --features "ssr,totp"
//! CARGO_BUILD_JOBS=1 cargo run -p lepton-auth --example step_up_totp --features "ssr,totp"
//! ```
//!
//! Success: stderr prints `step_up_totp: OK — verify_totp_for_session + require_recent_verification + verify_fresh_totp`.

#![allow(clippy::print_stderr, dead_code)]

use lepton_auth::{
    require_recent_verification, verify_fresh_totp, verify_totp_for_session, StepUpScope,
    STEP_UP_TTL_SECS,
};

fn main() {
    let _ = verify_totp_for_session;
    let _ = require_recent_verification;
    let _ = verify_fresh_totp;
    let _ = StepUpScope::SensitiveMutation;
    const { assert!(STEP_UP_TTL_SECS >= 60) };
    eprintln!(
        "step_up_totp: OK — verify_totp_for_session + require_recent_verification + verify_fresh_totp"
    );
}
