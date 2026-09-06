//! Server function that opens a TOTP sudo window for sensitive mutations.

use leptos::prelude::*;

/// Verify a TOTP code and open a 5-minute step-up window on the session.
///
/// Call from `lepton-auth-ui`'s `StepUpController` before retrying a gated
/// mutation. Returns the unix expiry second on success.
///
/// # Errors
///
/// [`ServerFnError`] with a `STEP_UP:<reason_class>:` prefix when verification
/// fails (enrollment required, invalid code, rate limited, etc.).
#[cfg(all(feature = "ssr", feature = "totp"))]
#[server(VerifyStepUpTotp)]
pub async fn verify_step_up_totp(
    /// Authenticator app code.
    totp_code: String,
) -> Result<i64, ServerFnError> {
    use crate::step_up::{verify_totp_for_session, StepUpScope};

    let outcome = verify_totp_for_session(StepUpScope::SensitiveMutation, &totp_code)
        .await
        .map_err(|e| e.to_server_fn_error())?;
    Ok(outcome.window_expires_at().timestamp())
}

#[cfg(not(all(feature = "ssr", feature = "totp")))]
/// Stub when `totp` is off: always returns `STEP_UP:totp_unavailable`.
#[server(VerifyStepUpTotp)]
pub async fn verify_step_up_totp(
    /// Unused when the `totp` feature is disabled.
    totp_code: String,
) -> Result<i64, ServerFnError> {
    let _ = totp_code;
    Err(ServerFnError::new(
        "STEP_UP:totp_unavailable: totp feature disabled",
    ))
}
