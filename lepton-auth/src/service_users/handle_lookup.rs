//! Is a handle already taken, across every owner's service users?

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
/// # Errors
///
/// [`ServiceUserError::HandleTaken`] (with `suggestion: None`) when every candidate is
/// taken; [`ServiceUserError::Store`] on a storage failure.
pub(super) async fn first_free(
    valence: &Valence,
    handle: ServiceUserHandle,
) -> Result<ServiceUserHandle, ServiceUserError> {
    if !handle_key_taken(valence, &handle.key()).await? {
        return Ok(handle);
    }
    for candidate in handle.suggestions() {
        if !handle_key_taken(valence, &candidate.key()).await? {
            return Ok(candidate);
        }
    }
    Err(ServiceUserError::HandleTaken { suggestion: None })
}
