//! Verify TOTP and open / require the session sudo window.

use chrono::Utc;
use lepton_host_adapter::generated::TotpFactor;
use lepton_host_adapter::User;
use leptos_axum::extract;
use tower_sessions::Session;
use valence::{RecordId, Valence};

use super::error::StepUpError;
use super::scope::StepUpScope;
use super::throttle::{is_locked, record_failure};
use super::window::{self, store_window};
use crate::factor::verify_totp_against_sealed;
use crate::ssr_support::{extract_auth_user, higgs_ctx};
use crate::totp::seal::{is_sealed_envelope, seal_totp_secret, unseal_totp_secret};

/// Successful window open.
#[derive(Clone, Debug)]
pub struct StepUpOutcome {
    expires_at: chrono::DateTime<Utc>,
}

impl StepUpOutcome {
    /// When the sudo window expires.
    #[must_use]
    pub const fn window_expires_at(&self) -> chrono::DateTime<Utc> {
        self.expires_at
    }
}

fn bare_user_id(user: &User) -> String {
    user.session_id.clone()
}

fn user_record(user: &User) -> RecordId {
    RecordId::new("user", bare_user_id(user))
}

const fn current_step(now_secs: i64) -> i64 {
    now_secs.div_euclid(30)
}

/// Whether this TOTP time-step was already accepted (same-step replay).
#[must_use]
fn step_already_used(last_used_step: Option<i64>, now_secs: i64) -> bool {
    last_used_step == Some(current_step(now_secs))
}

async fn load_enabled_factor(
    valence: &Valence,
    user: &RecordId,
) -> Result<TotpFactor, StepUpError> {
    let uid = valence::extract_id_from_record(user).unwrap_or_else(|_| user.id().to_string());
    let factors = TotpFactor::get_from_user_id(&uid, valence)
        .await
        .map_err(|_| StepUpError::Store)?;
    factors
        .into_iter()
        .find(|f| f.enabled_at().is_some())
        .ok_or(StepUpError::TotpEnrollmentRequired)
}

async fn apply_failure(
    valence: &Valence,
    factor: &TotpFactor,
    failed_attempts: i64,
    now: chrono::DateTime<Utc>,
) -> Result<StepUpError, StepUpError> {
    let (next, locked_until) = record_failure(failed_attempts, now);
    let mut mutable = factor
        .get_mutable(valence)
        .set_failed_attempts(next)
        .map_err(|_| StepUpError::Store)?;
    mutable = if let Some(until) = locked_until {
        mutable
            .set_locked_until(until)
            .map_err(|_| StepUpError::Store)?
    } else {
        mutable.clear_locked_until()
    };
    mutable
        .set_updated_at(now)
        .map_err(|_| StepUpError::Store)?
        .commit()
        .await
        .map_err(|_| StepUpError::Store)?;
    if locked_until.is_some() {
        Ok(StepUpError::StepUpRateLimited)
    } else {
        Ok(StepUpError::StepUpInvalid)
    }
}

async fn apply_success(
    valence: &Valence,
    factor: &TotpFactor,
    secret_sealed: &str,
    step: i64,
    now: chrono::DateTime<Utc>,
) -> Result<(), StepUpError> {
    let mut sealed = secret_sealed.to_string();
    if !is_sealed_envelope(&sealed) {
        sealed = seal_totp_secret(&sealed).map_err(|_| StepUpError::TotpSecret)?;
    }
    factor
        .get_mutable(valence)
        .set_secret_sealed(sealed)
        .map_err(|_| StepUpError::Store)?
        .set_last_used_step(step)
        .map_err(|_| StepUpError::Store)?
        .set_failed_attempts(0)
        .map_err(|_| StepUpError::Store)?
        .clear_locked_until()
        .set_updated_at(now)
        .map_err(|_| StepUpError::Store)?
        .commit()
        .await
        .map_err(|_| StepUpError::Store)?;
    Ok(())
}

/// Verify a TOTP code against a loaded factor (throttle, same-step replay, seal/migrate).
///
/// Used by [`verify_totp_for_session`] and [`verify_fresh_totp`]. Exposed so library
/// tests (and hosts that already hold a [`TotpFactor`] under System Valence) can
/// exercise the verify core without a Leptos session extract.
///
/// # Errors
///
/// See [`StepUpError`].
pub async fn verify_code_against_factor(
    valence: &Valence,
    factor: &TotpFactor,
    code: &str,
    now: chrono::DateTime<Utc>,
) -> Result<(), StepUpError> {
    if is_locked(factor.locked_until(), now) {
        return Err(StepUpError::StepUpRateLimited);
    }
    let failed = factor.failed_attempts().copied().unwrap_or(0);
    let step = current_step(now.timestamp());
    if step_already_used(factor.last_used_step().copied(), now.timestamp()) {
        return Err(apply_failure(valence, factor, failed, now).await?);
    }
    let open = unseal_totp_secret(factor.secret_sealed()).map_err(|e| match e {
        crate::factor::FactorChallengeError::TotpSecret => StepUpError::TotpSecret,
        _ => StepUpError::StepUpInvalid,
    })?;
    match verify_totp_against_sealed(&open, code, Some(now.timestamp().cast_unsigned())) {
        Ok(()) => {
            apply_success(valence, factor, factor.secret_sealed(), step, now).await?;
            Ok(())
        }
        Err(_) => Err(apply_failure(valence, factor, failed, now).await?),
    }
}

/// Verify a TOTP code and open a session sudo window for `scope`.
///
/// # Errors
///
/// See [`StepUpError`].
pub async fn verify_totp_for_session(
    scope: StepUpScope,
    code: &str,
) -> Result<StepUpOutcome, StepUpError> {
    let (_ctx, user) = require_signed_in().await?;
    let session: Session = extract().await.map_err(|_| StepUpError::Store)?;
    let system = system_valence_for_totp().await?;
    let record = user_record(&user);
    let factor = load_enabled_factor(&system, &record).await?;
    let now = Utc::now();
    verify_code_against_factor(&system, &factor, code, now).await?;
    let expires = store_window(
        &session,
        &bare_user_id(&user),
        user.session_stamp.as_slice(),
        scope,
        now,
    )
    .await?;
    Ok(StepUpOutcome {
        expires_at: expires,
    })
}

/// Assert an unexpired window for `scope` bound to the current user/session.
///
/// # Errors
///
/// [`StepUpError::StepUpRequired`] / [`StepUpError::StepUpExpired`] / auth errors.
pub async fn require_recent_verification(scope: StepUpScope) -> Result<(), StepUpError> {
    let (_ctx, user) = require_signed_in().await?;
    let session: Session = extract().await.map_err(|_| StepUpError::Store)?;
    let Some(loaded) = window::load_window(&session).await? else {
        return Err(StepUpError::StepUpRequired);
    };
    if loaded.scope != scope {
        return Err(StepUpError::StepUpRequired);
    }
    if !window::window_matches_identity(
        &loaded,
        &bare_user_id(&user),
        user.session_stamp.as_slice(),
    ) {
        window::clear_window(&session).await;
        return Err(StepUpError::StepUpRequired);
    }
    let now = Utc::now();
    if loaded.expires_at <= now {
        window::clear_window(&session).await;
        return Err(StepUpError::StepUpExpired);
    }
    Ok(())
}

/// Verify a TOTP code without consulting or opening a window (`fresh` mode).
///
/// # Errors
///
/// See [`StepUpError`].
pub async fn verify_fresh_totp(code: &str) -> Result<(), StepUpError> {
    let (_ctx, user) = require_signed_in().await?;
    let system = system_valence_for_totp().await?;
    let record = user_record(&user);
    let factor = load_enabled_factor(&system, &record).await?;
    let now = Utc::now();
    verify_code_against_factor(&system, &factor, code, now).await
}

/// Fresh TOTP verify bound to a Higgs session user id (no axum-login).
///
/// Lab hosts that inject a Higgs session snapshot without
/// `AuthSession` use this for `IsolatedLab` fresh gates. Production product
/// hosts should prefer [`verify_fresh_totp`].
///
/// `session_user_id` may be bare (`admin`) or `user:admin`.
///
/// # Errors
///
/// See [`StepUpError`].
pub async fn verify_fresh_totp_for_session_user(
    session_user_id: &str,
    code: &str,
) -> Result<(), StepUpError> {
    let system = system_valence_for_totp().await?;
    let bare = session_user_id
        .split(':')
        .next_back()
        .unwrap_or(session_user_id);
    let record = RecordId::new("user", bare);
    let factor = load_enabled_factor(&system, &record).await?;
    let now = Utc::now();
    verify_code_against_factor(&system, &factor, code, now).await
}

async fn require_signed_in() -> Result<(higgs::Higgs, User), StepUpError> {
    match (higgs_ctx().await, extract_auth_user().await) {
        (Ok(ctx), Ok(user)) => {
            if ctx.session_user_id().is_none() {
                return Err(StepUpError::AuthRequired);
            }
            Ok((ctx, user))
        }
        _ => Err(StepUpError::AuthRequired),
    }
}

async fn system_valence_for_totp() -> Result<Valence, StepUpError> {
    let ctx = higgs_ctx().await.map_err(|_| StepUpError::AuthRequired)?;
    // TotpFactor is SYSTEM_ONLY; factor secrets are never exposed to session actors.
    ctx.unsafe_system_valence().map_err(|_| StepUpError::Store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::step_up::scope::StepUpMode;

    #[test]
    fn same_step_replay_denied() {
        let now = 1_700_000_030_i64;
        let step = current_step(now);
        assert!(step_already_used(Some(step), now));
        assert!(!step_already_used(Some(step - 1), now));
        assert!(!step_already_used(None, now));
    }

    #[test]
    fn window_ttl_is_five_minutes() {
        assert_eq!(crate::session_binding::STEP_UP_TTL_SECS, 300);
    }

    #[test]
    fn fresh_verify_path_skips_window_contract() {
        // Documented contract: verify_fresh_totp never calls load_window / store_window.
        assert!(!StepUpMode::Fresh.consults_session_window());
        assert!(StepUpMode::Window.consults_session_window());
    }
}
