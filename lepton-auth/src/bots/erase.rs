//! Bots removed together with their owner.

use lepton_host_adapter::generated::Bot;
use valence::Valence;

/// Bare ids of every bot `owner` owns, for account erasure to delete.
///
/// Runs under the erasing actor: the owner, or System for an erasure job.
pub async fn owned_bot_ids(valence: &Valence, owner: &str) -> valence::Result<Vec<String>> {
    let bots = Bot::get_from_user_id(
        owner,
        valence,
        valence::use_!(r"During **account erasure**, we **list the bot accounts this user owns** so each one is removed with the rest of the account. Only the erasure path uses this list."),
    )
    .await?;
    Ok(bots
        .iter()
        .filter_map(Bot::id)
        .map(|rid| valence::extract_id_from_record(rid).unwrap_or_else(|_| rid.id().to_string()))
        .collect())
}
