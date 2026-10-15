//! Is a handle already taken, across every owner's bots?

use lepton_identity::bots::BotHandle;
use valence::{CompiledQuery, Valence};

use super::BotError;

/// True when any bot, whoever owns it, already uses this clash key.
///
/// The caller can only read its own bots, so a privacy-filtered query would
/// miss other owners' handles. This reads the `handle_key` column directly and
/// returns only whether a match exists: no ids or other fields leave this
/// function. Callers check the bot gate first, so only bot creators can probe.
pub(super) async fn handle_key_taken(valence: &Valence, key: &str) -> Result<bool, BotError> {
    let backend = valence
        .backend_for_table("bot")
        .map_err(|_| BotError::Store)?;
    let compiled = CompiledQuery::new(
        "SELECT id FROM bot WHERE handle_key = $key LIMIT 1".to_string(),
        vec![(
            "key".to_string(),
            serde_json::Value::String(key.to_string()),
        )],
    );
    let rows = backend
        .execute_compiled_query(&compiled)
        .await
        .map_err(|_| BotError::Store)?;
    Ok(!rows.is_empty())
}

/// `handle` itself when free, otherwise the first free suggestion.
///
/// # Errors
///
/// [`BotError::HandleTaken`] (with `suggestion: None`) when every candidate is
/// taken; [`BotError::Store`] on a storage failure.
pub(super) async fn first_free(
    valence: &Valence,
    handle: BotHandle,
) -> Result<BotHandle, BotError> {
    if !handle_key_taken(valence, &handle.key()).await? {
        return Ok(handle);
    }
    for candidate in handle.suggestions() {
        if !handle_key_taken(valence, &candidate.key()).await? {
            return Ok(candidate);
        }
    }
    Err(BotError::HandleTaken { suggestion: None })
}
