//! Is a handle already taken, across every owner's service users?

use std::collections::HashSet;

use lepton_identity::service_users::ServiceUserHandle;
use valence::{CompiledQuery, Valence};

use super::ServiceUserError;

/// True when any service user, whoever owns it, already uses this clash key.
///
/// The caller can only read its own service users, so a privacy-filtered query would
/// miss other owners' handles. This reads the `handle_key` column directly and
/// returns only whether a match exists: no ids or other fields leave this
/// function. Callers check the service user gate first, so only service user creators can probe.
///
/// A service user whose deletion is still running keeps its handle until the row is
/// purged, matching the `unique: true` constraint; the handle frees for reuse once
/// the row is gone.
pub(super) async fn handle_key_taken(
    valence: &Valence,
    key: &str,
) -> Result<bool, ServiceUserError> {
    let backend = valence
        .backend_for_table("service_user_account")
        .map_err(|_| ServiceUserError::Misconfigured)?;
    let compiled = CompiledQuery::new(
        "SELECT id FROM service_user_account WHERE handle_key = $key LIMIT 1".to_string(),
        vec![(
            "key".to_string(),
            serde_json::Value::String(key.to_string()),
        )],
    );
    let rows = backend
        .execute_compiled_query(&compiled)
        .await
        .map_err(|_| ServiceUserError::Store)?;
    Ok(!rows.is_empty())
}

/// `handle` itself when free, otherwise the first free suggestion.
///
/// Reads every candidate's clash key in one query, then picks in order. Like
/// [`handle_key_taken`], only the matching keys come back.
///
/// # Errors
///
/// [`ServiceUserError::HandleTaken`] (with `suggestion: None`) when every candidate is
/// taken; [`ServiceUserError::Store`] on a storage failure.
pub(super) async fn first_free(
    valence: &Valence,
    handle: ServiceUserHandle,
) -> Result<ServiceUserHandle, ServiceUserError> {
    let candidates: Vec<ServiceUserHandle> = std::iter::once(handle.clone())
        .chain(handle.suggestions())
        .collect();
    let keys: Vec<serde_json::Value> = candidates
        .iter()
        .map(|c| serde_json::Value::String(c.key()))
        .collect();
    let backend = valence
        .backend_for_table("service_user_account")
        .map_err(|_| ServiceUserError::Misconfigured)?;
    let compiled = CompiledQuery::new(
        "SELECT handle_key FROM service_user_account WHERE handle_key IN $keys".to_string(),
        vec![("keys".to_string(), serde_json::Value::Array(keys))],
    );
    let rows = backend
        .execute_compiled_query(&compiled)
        .await
        .map_err(|_| ServiceUserError::Store)?;
    let taken: HashSet<String> = rows
        .iter()
        .filter_map(|row| row.get("handle_key").and_then(serde_json::Value::as_str))
        .map(str::to_string)
        .collect();
    first_free_from(candidates, &taken).ok_or(ServiceUserError::HandleTaken { suggestion: None })
}

/// The first candidate whose clash key is not in `taken`.
fn first_free_from(
    candidates: Vec<ServiceUserHandle>,
    taken: &HashSet<String>,
) -> Option<ServiceUserHandle> {
    candidates.into_iter().find(|c| !taken.contains(&c.key()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle(text: &str) -> ServiceUserHandle {
        ServiceUserHandle::parse(text).unwrap_or_else(|e| panic!("{text}: {e}"))
    }

    #[test]
    fn first_free_from_picks_first_untaken_happy() {
        let base = handle("spectra");
        let candidates: Vec<_> = std::iter::once(base.clone())
            .chain(base.suggestions())
            .collect();
        let none = HashSet::new();
        assert_eq!(first_free_from(candidates.clone(), &none), Some(base));
        let taken: HashSet<String> = ["spectra", "spectra2", "spectra3"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(
            first_free_from(candidates, &taken),
            Some(handle("spectra-4"))
        );
    }

    #[test]
    fn first_free_from_all_taken_sad() {
        let base = handle("spectra");
        let candidates: Vec<_> = std::iter::once(base.clone())
            .chain(base.suggestions())
            .collect();
        let taken: HashSet<String> = candidates.iter().map(ServiceUserHandle::key).collect();
        assert_eq!(first_free_from(candidates, &taken), None);
    }
}
