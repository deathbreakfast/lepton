//! Product erase hooks that run before a Lepton user is deleted.
//!
//! Lepton deletes the user rows it owns and nothing else. A product that keeps
//! data a plain user delete can't remove (rows behind `Restrict` edges, files,
//! scheduled jobs) registers a [`UserEraseHook`]. [`crate::identity_delete`]
//! runs every registered hook for a user before it deletes the user row and the
//! user-owned children (devices, factors, linked identities), on both [`erase_account`](crate::identity_delete::erase_account) and
//! [`delete_user`](crate::identity_delete::delete_user).
//!
//! ## Register a product erase step
//!
//! **Prerequisites:** `ssr` feature; a host that erases users with a System
//! Valence, which is the Valence the hook receives.
//!
//! ```rust,ignore
//! struct FinanceErase;
//!
//! #[async_trait::async_trait]
//! impl lepton_auth::erase_hooks::UserEraseHook for FinanceErase {
//!     fn name(&self) -> &'static str { "finance" }
//!
//!     async fn erase_user(
//!         &self,
//!         user_id: &str,
//!         valence: &valence::Valence,
//!     ) -> Result<(), lepton_auth::erase_hooks::UserEraseHookError> {
//!         finance::erase::erase_user_owned_workspace(user_id, valence)
//!             .await
//!             .map(|_| ())
//!             .map_err(|_| lepton_auth::erase_hooks::UserEraseHookError::new("finance erase failed"))
//!     }
//! }
//!
//! lepton_auth::erase_hooks::register_user_erase_hook(std::sync::Arc::new(FinanceErase));
//! ```
//!
//! A hook may do the work inline or enqueue a job and wait for it; it only has
//! to return once the product's data for that user is gone.
//!
//! ## Contract
//!
//! - Hooks run in registration order and stop at the first failure. The user
//!   delete is then skipped and the caller gets
//!   [`IdentityDeleteError::EraseHook`](crate::identity_delete::IdentityDeleteError::EraseHook).
//! - [`erase_account`](crate::identity_delete::erase_account) deletes the account,
//!   its contacts and memberships first, then deletes each member user, so the
//!   hooks run after those rows are gone. When a hook fails there, no account is
//!   left: retry with [`delete_user`](crate::identity_delete::delete_user) for
//!   each member user.
//! - A hook can run more than once for the same user (a retry after a partial
//!   failure, or a user with no product data), so it has to be idempotent.
//! - Registering a second hook with the same [`name`](UserEraseHook::name)
//!   replaces the first, so host boot code can run more than once.

use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use thiserror::Error;
use valence::Valence;

/// A product's erase step, run before the Lepton user delete.
#[async_trait]
pub trait UserEraseHook: Send + Sync {
    /// Stable identifier, used for replacement and in logs.
    fn name(&self) -> &'static str;

    /// Remove the product's data for `user_id` (the bare user id).
    ///
    /// # Errors
    ///
    /// [`UserEraseHookError`] when the product's data could not be removed. The
    /// user is not deleted.
    async fn erase_user(&self, user_id: &str, valence: &Valence) -> Result<(), UserEraseHookError>;
}

/// A [`UserEraseHook`] failed. The message is logged, never returned to callers.
///
/// Keep the message free of PII and secrets (user ids, emails, tokens): write a
/// fixed description of what failed, not an upstream error's `to_string()`.
#[derive(Debug, Error)]
#[error("{0}")]
pub struct UserEraseHookError(String);

impl UserEraseHookError {
    /// Wrap a failure message.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

static HOOKS: RwLock<Vec<Arc<dyn UserEraseHook>>> = RwLock::new(Vec::new());

/// Register `hook`, replacing any hook with the same [`name`](UserEraseHook::name).
pub fn register_user_erase_hook(hook: Arc<dyn UserEraseHook>) {
    let mut hooks = HOOKS
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match hooks.iter_mut().find(|h| h.name() == hook.name()) {
        Some(existing) => *existing = hook,
        None => hooks.push(hook),
    }
}

/// Remove the hook registered under `name`; returns whether one was registered.
pub fn unregister_user_erase_hook(name: &str) -> bool {
    let mut hooks = HOOKS
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let before = hooks.len();
    hooks.retain(|h| h.name() != name);
    hooks.len() != before
}

/// Run every registered hook for `user_id`, in order. Returns the name of the
/// first hook that failed.
pub(crate) async fn run_user_erase_hooks(
    user_id: &str,
    valence: &Valence,
) -> Result<(), &'static str> {
    let hooks: Vec<Arc<dyn UserEraseHook>> = HOOKS
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    for hook in hooks {
        if let Err(e) = hook.erase_user(user_id, valence).await {
            tracing::error!(
                hook = hook.name(),
                error = %e,
                "lepton_auth.erase_hooks: product erase hook failed; user not deleted"
            );
            return Err(hook.name());
        }
    }
    Ok(())
}
