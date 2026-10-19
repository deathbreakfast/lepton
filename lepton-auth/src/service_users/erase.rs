//! Service users removed together with their owner.

use lepton_host_adapter::generated::ServiceUserAccount;
use valence::Valence;

/// Bare ids of every service user `owner` owns, for account erasure to delete.
///
/// Runs under the erasing actor: the owner, or System for an erasure job.
pub async fn owned_service_user_ids(
    valence: &Valence,
    owner: &str,
) -> valence::Result<Vec<String>> {
    let service_users = ServiceUserAccount::get_from_user_id(
        owner,
        valence,
        valence::use_!(r"During **account erasure**, we **list the service users this user owns** so each one is removed with the rest of the account. Only the erasure path uses this list."),
    )
    .await?;
    Ok(service_users
        .iter()
        .filter_map(ServiceUserAccount::id)
        .map(|rid| valence::extract_id_from_record(rid).unwrap_or_else(|_| rid.id().to_string()))
        .collect())
}
