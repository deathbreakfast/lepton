//! Session bag keys for the TOTP sudo window (delegates to [`crate::session_binding`]).

use chrono::{DateTime, Utc};
use tower_sessions::Session;

use super::error::StepUpError;
use super::scope::StepUpScope;
use crate::session_binding::{
    clear_step_up_window, STEP_UP_AUTH_HASH_KEY, STEP_UP_EXPIRES_AT_KEY, STEP_UP_SCOPE_KEY,
    STEP_UP_TTL_SECS, STEP_UP_USER_ID_KEY, STEP_UP_VERIFIED_AT_KEY,
};

/// Persist a fresh window on the session.
pub async fn store_window(
    session: &Session,
    user_id: &str,
    auth_hash: &[u8],
    scope: StepUpScope,
    now: DateTime<Utc>,
) -> Result<DateTime<Utc>, StepUpError> {
    let expires = now + chrono::Duration::seconds(STEP_UP_TTL_SECS);
    session
        .insert(STEP_UP_VERIFIED_AT_KEY, now.timestamp())
        .await
        .map_err(|_| StepUpError::Store)?;
    session
        .insert(STEP_UP_EXPIRES_AT_KEY, expires.timestamp())
        .await
        .map_err(|_| StepUpError::Store)?;
    session
        .insert(STEP_UP_USER_ID_KEY, user_id.to_string())
        .await
        .map_err(|_| StepUpError::Store)?;
    session
        .insert(STEP_UP_AUTH_HASH_KEY, auth_hash.to_vec())
        .await
        .map_err(|_| StepUpError::Store)?;
    session
        .insert(STEP_UP_SCOPE_KEY, scope.as_str().to_string())
        .await
        .map_err(|_| StepUpError::Store)?;
    Ok(expires)
}

/// Drop the window (logout / credential change).
pub async fn clear_window(session: &Session) {
    clear_step_up_window(session).await;
}

/// Loaded window fields used by require.
pub struct LoadedWindow {
    /// Expiry instant.
    pub expires_at: DateTime<Utc>,
    /// Bound user id.
    pub user_id: String,
    /// Bound auth hash.
    pub auth_hash: Vec<u8>,
    /// Bound scope.
    pub scope: StepUpScope,
}

/// Whether `loaded` is bound to this user id and auth-hash (require identity check).
#[must_use]
pub fn window_matches_identity(loaded: &LoadedWindow, user_id: &str, auth_hash: &[u8]) -> bool {
    loaded.user_id == user_id && loaded.auth_hash.as_slice() == auth_hash
}

/// Read the window if present (does not clear on expiry; caller decides).
pub async fn load_window(session: &Session) -> Result<Option<LoadedWindow>, StepUpError> {
    let Some(expires_ts) = session
        .get::<i64>(STEP_UP_EXPIRES_AT_KEY)
        .await
        .map_err(|_| StepUpError::Store)?
    else {
        return Ok(None);
    };
    let user_id = session
        .get::<String>(STEP_UP_USER_ID_KEY)
        .await
        .map_err(|_| StepUpError::Store)?
        .ok_or(StepUpError::Store)?;
    let auth_hash = session
        .get::<Vec<u8>>(STEP_UP_AUTH_HASH_KEY)
        .await
        .map_err(|_| StepUpError::Store)?
        .ok_or(StepUpError::Store)?;
    let scope_raw = session
        .get::<String>(STEP_UP_SCOPE_KEY)
        .await
        .map_err(|_| StepUpError::Store)?
        .ok_or(StepUpError::Store)?;
    let Some(scope) = StepUpScope::parse(&scope_raw) else {
        clear_window(session).await;
        return Ok(None);
    };
    let Some(expires_at) = DateTime::from_timestamp(expires_ts, 0) else {
        clear_window(session).await;
        return Ok(None);
    };
    Ok(Some(LoadedWindow {
        expires_at,
        user_id,
        auth_hash,
        scope,
    }))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use tower_sessions::{MemoryStore, Session};

    use crate::session_binding::STEP_UP_TTL_SECS;
    use crate::step_up::scope::StepUpScope;

    fn memory_session() -> Session {
        let store = Arc::new(MemoryStore::default());
        Session::new(None, store, None)
    }

    #[tokio::test]
    async fn store_and_load_window_happy() {
        let session = memory_session();
        let now = Utc::now();
        let expires = store_window(
            &session,
            "user-1",
            b"auth-hash",
            StepUpScope::SensitiveMutation,
            now,
        )
        .await
        .expect("store");
        // Session bag stores second timestamps; expiry is TTL from truncated now.
        assert_eq!(
            expires.timestamp(),
            (now + chrono::Duration::seconds(STEP_UP_TTL_SECS)).timestamp()
        );

        let loaded = load_window(&session).await.expect("load").expect("present");
        assert_eq!(loaded.user_id, "user-1");
        assert_eq!(loaded.auth_hash, b"auth-hash");
        assert_eq!(loaded.scope, StepUpScope::SensitiveMutation);
        assert_eq!(loaded.expires_at.timestamp(), expires.timestamp());
        assert!(loaded.expires_at.timestamp() > now.timestamp());
    }

    #[tokio::test]
    async fn store_window_expiry_past_sad() {
        let session = memory_session();
        let past = Utc::now() - chrono::Duration::seconds(STEP_UP_TTL_SECS + 60);
        let expires = store_window(
            &session,
            "user-1",
            b"auth-hash",
            StepUpScope::SensitiveMutation,
            past,
        )
        .await
        .expect("store");
        assert!(
            expires <= Utc::now(),
            "stored window must already be expired"
        );

        let loaded = load_window(&session).await.expect("load").expect("present");
        // Mirror require_recent_verification: expires_at <= now ⇒ StepUpExpired.
        assert!(
            loaded.expires_at <= Utc::now(),
            "loaded window must fail the unexpired check"
        );
    }

    #[tokio::test]
    async fn clear_window_removes_step_up_keys_happy() {
        let session = memory_session();
        let now = Utc::now();
        store_window(
            &session,
            "user-1",
            b"auth-hash",
            StepUpScope::SensitiveMutation,
            now,
        )
        .await
        .expect("store");
        assert!(load_window(&session).await.expect("load").is_some());

        clear_window(&session).await;

        assert!(
            load_window(&session)
                .await
                .expect("load after clear")
                .is_none(),
            "clear_window must drop all step-up session keys"
        );
        assert!(session
            .get::<i64>(crate::session_binding::STEP_UP_EXPIRES_AT_KEY)
            .await
            .expect("get")
            .is_none());
        assert!(session
            .get::<String>(crate::session_binding::STEP_UP_USER_ID_KEY)
            .await
            .expect("get")
            .is_none());
        assert!(session
            .get::<Vec<u8>>(crate::session_binding::STEP_UP_AUTH_HASH_KEY)
            .await
            .expect("get")
            .is_none());
    }

    #[tokio::test]
    async fn window_wrong_user_or_auth_hash_rejected_sad() {
        // TM-3 session/credential bind: require_recent_verification rejects when the
        // window's user_id or auth_hash does not match the live session identity.
        // Password-change / logout clear is covered by `tests/step_up_session_binding.rs`.
        let session = memory_session();
        let now = Utc::now();
        store_window(
            &session,
            "user-1",
            b"auth-hash-a",
            StepUpScope::SensitiveMutation,
            now,
        )
        .await
        .expect("store");
        let loaded = load_window(&session).await.expect("load").expect("present");

        assert!(window_matches_identity(&loaded, "user-1", b"auth-hash-a"));
        // Mirror require_recent_verification: mismatched binding ⇒ StepUpRequired.
        assert!(!window_matches_identity(
            &loaded,
            "user-other",
            b"auth-hash-a"
        ));
        assert!(!window_matches_identity(&loaded, "user-1", b"auth-hash-b"));
        // Both wrong: still fail closed.
        assert!(!window_matches_identity(
            &loaded,
            "user-other",
            b"auth-hash-b"
        ));
    }
}
