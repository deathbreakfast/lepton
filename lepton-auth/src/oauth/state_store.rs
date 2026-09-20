//! Valence-backed OAuth CSRF + PKCE pending state.

use chrono::{Duration, Utc};
use lepton_host_adapter::generated::{
    OauthPendingState, OauthPendingStateIntent, OauthPendingStateProvider,
};
use valence::{Model, Valence};

use super::error::OAuthError;
use super::{OAuthIntent, OAuthProvider};
use crate::security::random_token_part;

/// Pending OAuth begin → complete window.
pub(super) const OAUTH_PENDING_TTL_MINUTES: i64 = 10;

#[derive(Clone, Debug)]
pub(super) struct PendingState {
    pub provider: OAuthProvider,
    pub intent: OAuthIntent,
    pub link_user: Option<String>,
    pub pkce_verifier: String,
    pub referer: Option<String>,
}

const fn to_provider(p: OAuthProvider) -> OauthPendingStateProvider {
    match p {
        OAuthProvider::Google => OauthPendingStateProvider::Google,
        OAuthProvider::GitHub => OauthPendingStateProvider::Github,
    }
}

const fn from_provider(p: &OauthPendingStateProvider) -> OAuthProvider {
    match p {
        OauthPendingStateProvider::Google => OAuthProvider::Google,
        OauthPendingStateProvider::Github => OAuthProvider::GitHub,
    }
}

const fn to_intent(i: OAuthIntent) -> OauthPendingStateIntent {
    match i {
        OAuthIntent::Login => OauthPendingStateIntent::Login,
        OAuthIntent::Signup => OauthPendingStateIntent::Signup,
        OAuthIntent::Link => OauthPendingStateIntent::Link,
    }
}

const fn from_intent(i: &OauthPendingStateIntent) -> OAuthIntent {
    match i {
        OauthPendingStateIntent::Login => OAuthIntent::Login,
        OauthPendingStateIntent::Signup => OAuthIntent::Signup,
        OauthPendingStateIntent::Link => OAuthIntent::Link,
    }
}

fn from_row(row: &OauthPendingState) -> PendingState {
    PendingState {
        provider: from_provider(row.provider()),
        intent: from_intent(row.intent()),
        link_user: row.link_user().cloned(),
        pkce_verifier: row.pkce_verifier().clone(),
        referer: row.referer().cloned(),
    }
}

/// Persist a new pending state; returns the opaque CSRF `state` id.
pub(super) async fn put_state(
    valence: &Valence,
    pending: PendingState,
) -> Result<String, OAuthError> {
    let now = Utc::now();
    let expires_at = now + Duration::minutes(OAUTH_PENDING_TTL_MINUTES);
    let state = random_token_part(16);
    let row = OauthPendingState::new(
        to_provider(pending.provider),
        to_intent(pending.intent),
        pending.link_user,
        pending.pkce_verifier,
        pending.referer,
        expires_at,
        now,
        now,
    )
    .map_err(|_| OAuthError::Store)?;
    OauthPendingState::upsert_used(&state, row, valence, valence::use_!(r"When **OAuth account linking** needs to persist work, we **save Oauth Pending State** so the next step in that feature can continue with the latest values. People and services allowed for **OAuth account linking** use this data for that workflow—not as a general export of unrelated personal fields."))
        .await
        .map_err(|_| OAuthError::Store)?;
    Ok(state)
}

/// Consume pending state once (delete after load). Expired or missing → `None`.
pub(super) async fn take_state(
    valence: &Valence,
    state: &str,
) -> Result<Option<PendingState>, OAuthError> {
    let state = state.trim();
    if state.is_empty() {
        return Ok(None);
    }
    let Some(row) = OauthPendingState::get_used(state, valence, valence::use_!(r"In **OAuth account linking**, we **load Oauth Pending State** so the application can decide what to do next in this workflow. The result is used by **OAuth account linking** logic—not necessarily displayed on a page unless that feature’s UI shows it."))
        .await
        .map_err(|_| OAuthError::Store)?
    else {
        return Ok(None);
    };
    if *row.expires_at() < Utc::now() {
        let _ = delete_pending(valence, state).await;
        return Ok(None);
    }
    let pending = from_row(&row);
    delete_pending(valence, state).await?;
    Ok(Some(pending))
}

/// Read provider for `state` without consuming the CSRF entry.
pub async fn peek_provider(valence: &Valence, state: &str) -> Result<OAuthProvider, OAuthError> {
    let state = state.trim();
    if state.is_empty() {
        return Err(OAuthError::State);
    }
    let Some(row) = OauthPendingState::get_used(state, valence, valence::use_!(r"In **OAuth account linking**, we **load Oauth Pending State** so the application can decide what to do next in this workflow. The result is used by **OAuth account linking** logic—not necessarily displayed on a page unless that feature’s UI shows it."))
        .await
        .map_err(|_| OAuthError::Store)?
    else {
        return Err(OAuthError::State);
    };
    if *row.expires_at() < Utc::now() {
        return Err(OAuthError::State);
    }
    Ok(from_provider(row.provider()))
}

async fn delete_pending(valence: &Valence, state: &str) -> Result<(), OAuthError> {
    let backend = valence
        .backend_for_table("oauth_pending_state")
        .map_err(|_| OAuthError::Store)?;
    valence::delete_record_used(
        backend.as_ref(),
        "oauth_pending_state",
        state,
        valence::use_!(r"After an **OAuth link** finishes or expires, we **discard the pending state** so the one-time handshake token cannot be reused. Only the link flow uses this cleanup."),
    )
    .await
    .map_err(|_| OAuthError::Store)?;
    valence::read_cache::invalidate("oauth_pending_state", state);
    Ok(())
}
