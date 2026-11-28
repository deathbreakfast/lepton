//! The API scopes a host lets tokens carry.
//!
//! A scope names one API a token may call, such as `magnon:read`. The host registers its
//! scopes once at boot with [`register_api_scopes`], with the label the token form shows.
//! Lepton then mints tokens only with registered scopes ([`check_scopes`]), and the host
//! guards each API route with `lepton_host_adapter::require_scope`.
//!
//! ```
//! use lepton_auth::scopes::{register_api_scopes, registered_scopes, ScopeInfo};
//! use lepton_identity::tokens::ApiScope;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! register_api_scopes(vec![
//!     ScopeInfo::new(ApiScope::parse("magnon:read")?, "Magnon: Read tasks and projects"),
//!     ScopeInfo::new(ApiScope::parse("magnon:write")?, "Magnon: Change tasks and projects"),
//! ])?;
//! assert_eq!(registered_scopes().len(), 2);
//! # Ok(())
//! # }
//! ```
//!
//! Until a host registers scopes, nobody can mint a token.

use std::sync::OnceLock;

use lepton_identity::tokens::ApiScope;

/// One scope the host offers, with the label people see when they tick it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeInfo {
    /// The scope string a token carries.
    pub scope: ApiScope,
    /// What the scope lets a token call, such as `Magnon: Read tasks and projects`.
    pub label: String,
}

impl ScopeInfo {
    /// A scope with its label.
    #[must_use]
    pub fn new(scope: ApiScope, label: impl Into<String>) -> Self {
        Self {
            scope,
            label: label.into(),
        }
    }
}

/// [`register_api_scopes`] was already called in this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("reason_class=already_registered: API scopes are already registered")]
pub struct ScopesAlreadyRegistered;

/// Why a token's requested scopes were refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScopeError {
    /// The host never called [`register_api_scopes`]. A host configuration problem.
    #[error("reason_class=not_configured: no API scopes registered")]
    NotRegistered,
    /// No scope was ticked. A token must be able to call at least one API.
    #[error("reason_class=scopes: a token needs at least one scope")]
    Empty,
    /// A requested scope is not one the host registered.
    #[error("reason_class=scopes: scope is not registered")]
    Unknown(ApiScope),
}

static REGISTRY: OnceLock<Vec<ScopeInfo>> = OnceLock::new();

/// Register the host's scopes. Call once at boot, before serving requests.
///
/// # Errors
///
/// [`ScopesAlreadyRegistered`] on a second call; the first list stays.
pub fn register_api_scopes(scopes: Vec<ScopeInfo>) -> Result<(), ScopesAlreadyRegistered> {
    REGISTRY.set(scopes).map_err(|_| ScopesAlreadyRegistered)
}

/// The scopes the host registered, in its order. Empty until [`register_api_scopes`] runs.
#[must_use]
pub fn registered_scopes() -> &'static [ScopeInfo] {
    REGISTRY.get().map_or(&[], Vec::as_slice)
}

/// Check the scopes a new token asks for: at least one, every one registered. Returns them
/// sorted with duplicates removed, ready to store.
///
/// # Errors
///
/// See [`ScopeError`].
pub fn check_scopes(requested: &[ApiScope]) -> Result<Vec<ApiScope>, ScopeError> {
    check_against(REGISTRY.get().map(Vec::as_slice), requested)
}

fn check_against(
    registry: Option<&[ScopeInfo]>,
    requested: &[ApiScope],
) -> Result<Vec<ApiScope>, ScopeError> {
    let registry = registry.ok_or(ScopeError::NotRegistered)?;
    if requested.is_empty() {
        return Err(ScopeError::Empty);
    }
    if let Some(unknown) = requested
        .iter()
        .find(|s| !registry.iter().any(|info| &info.scope == *s))
    {
        return Err(ScopeError::Unknown(unknown.clone()));
    }
    let mut scopes = requested.to_vec();
    scopes.sort();
    scopes.dedup();
    Ok(scopes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(raw: &str) -> ApiScope {
        ApiScope::parse(raw).expect("scope")
    }

    fn registry() -> Vec<ScopeInfo> {
        vec![
            ScopeInfo::new(scope("magnon:read"), "Magnon: Read tasks and projects"),
            ScopeInfo::new(scope("files:read"), "Files: Read files"),
        ]
    }

    #[test]
    fn registered_scopes_pass_sorted_and_deduped_happy() {
        let reg = registry();
        let got = check_against(
            Some(&reg),
            &[
                scope("magnon:read"),
                scope("files:read"),
                scope("magnon:read"),
            ],
        )
        .expect("ok");
        assert_eq!(got, [scope("files:read"), scope("magnon:read")]);
    }

    #[test]
    fn unknown_or_empty_scopes_refused_sad() {
        let reg = registry();
        assert_eq!(check_against(Some(&reg), &[]), Err(ScopeError::Empty));
        assert_eq!(
            check_against(Some(&reg), &[scope("magnon:read"), scope("magnon:write")]),
            Err(ScopeError::Unknown(scope("magnon:write")))
        );
    }

    #[test]
    fn no_registry_refuses_everything_sad() {
        assert_eq!(
            check_against(None, &[scope("magnon:read")]),
            Err(ScopeError::NotRegistered)
        );
    }
}
