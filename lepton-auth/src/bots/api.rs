//! Create, read, edit, suspend, resume, and delete bots.

use chrono::Utc;
use lepton_host_adapter::generated::{Bot, BotOwnerKind, BotStatus};
use lepton_identity::bots::{installed_bot_gate, BotHandle, BotId};
use valence::ownership::OwnershipService;
use valence::{Actor, Model, RecordId, Valence};

use super::handle_lookup::{first_free, handle_key_taken};
use super::BotError;

const MAX_DISPLAY_NAME: usize = 80;
const MAX_DESCRIPTION: usize = 500;

/// Most bots one owner can have at once. Active and suspended bots count;
/// deleted ones (including deletions still running) do not. Super users are
/// held to the same limit for the bots they own.
pub const MAX_BOTS_PER_OWNER: usize = 10;

/// Profile for a new bot. See [`create_bot`].
#[derive(Debug, Clone, Copy)]
pub struct NewBot<'a> {
    /// Requested handle, for example `spectra-bot`. Must end in `bot`.
    pub handle: &'a str,
    /// Name shown next to the bot's actions (1–80 characters).
    pub display_name: &'a str,
    /// What the bot is for (at most 500 characters).
    pub description: Option<&'a str>,
}

/// Profile edits for [`update_bot`]. `None` leaves a field as it is.
#[derive(Debug, Clone, Copy, Default)]
pub struct BotProfileUpdate<'a> {
    /// New display name.
    pub display_name: Option<&'a str>,
    /// `Some(None)` clears the description; `Some(Some(text))` replaces it.
    pub description: Option<Option<&'a str>>,
}

#[derive(Debug, Clone, Copy)]
enum Op {
    Create,
    Update,
    Suspend,
    Resume,
    Delete,
}

impl Op {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Suspend => "suspend",
            Self::Resume => "resume",
            Self::Delete => "delete",
        }
    }
}

/// Log and count the outcome once, at the service boundary.
fn record<T>(op: Op, result: Result<T, BotError>, bot_id: Option<&BotId>) -> Result<T, BotError> {
    match &result {
        Ok(_) => tracing::info!(
            target: "lepton.bot",
            op = op.as_str(),
            bot_id = bot_id.map(BotId::as_str),
            "bot lifecycle"
        ),
        Err(e @ (BotError::Store | BotError::Gate(_))) => tracing::warn!(
            target: "lepton.bot",
            op = op.as_str(),
            reason_class = e.reason_class(),
            "bot lifecycle failed"
        ),
        Err(e) => tracing::debug!(
            target: "lepton.bot",
            op = op.as_str(),
            reason_class = e.reason_class(),
            "bot lifecycle refused"
        ),
    }
    #[cfg(feature = "spectra")]
    crate::spectra_emit::bot(
        match op {
            Op::Create => crate::spectra_emit::BotOperation::Create,
            Op::Update => crate::spectra_emit::BotOperation::Update,
            Op::Suspend => crate::spectra_emit::BotOperation::Suspend,
            Op::Resume => crate::spectra_emit::BotOperation::Resume,
            Op::Delete => crate::spectra_emit::BotOperation::Delete,
        },
        result.as_ref().err().map_or("none", BotError::reason_class),
    );
    result
}

/// The calling user's bare id, or [`BotError::NotAUser`].
fn caller_user(valence: &Valence) -> Result<String, BotError> {
    match valence.actor() {
        Actor::User { user_id } => {
            let bare = user_id
                .split_once(':')
                .map_or(user_id.as_str(), |(_, id)| id);
            Ok(bare.to_string())
        }
        _ => Err(BotError::NotAUser),
    }
}

/// Map a Valence write failure: a privacy refusal is [`BotError::Forbidden`].
const fn write_error(e: &valence::Error) -> BotError {
    match e {
        valence::Error::Privacy(_) => BotError::Forbidden,
        _ => BotError::Store,
    }
}

fn check_display_name(name: &str) -> Result<String, BotError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > MAX_DISPLAY_NAME {
        return Err(BotError::InvalidProfile {
            field: "display_name",
        });
    }
    Ok(name.to_string())
}

fn check_description(text: Option<&str>) -> Result<Option<String>, BotError> {
    let Some(text) = text.map(str::trim).filter(|t| !t.is_empty()) else {
        return Ok(None);
    };
    if text.chars().count() > MAX_DESCRIPTION {
        return Err(BotError::InvalidProfile {
            field: "description",
        });
    }
    Ok(Some(text.to_string()))
}

/// The status after moving to `to`, or [`BotError::InvalidTransition`] when the
/// bot is already there.
fn transition(from: &BotStatus, to: BotStatus) -> Result<BotStatus, BotError> {
    if *from == to {
        Err(BotError::InvalidTransition { from: to })
    } else {
        Ok(to)
    }
}

/// Ask the installed gate whether the caller may create bots.
async fn require_create_permission(valence: &Valence) -> Result<(), BotError> {
    let gate = installed_bot_gate().ok_or(BotError::GateNotInstalled)?;
    if gate.may_create_bot(valence).await.map_err(BotError::Gate)? {
        Ok(())
    } else {
        Err(BotError::CreateNotPermitted)
    }
}

/// Create a bot owned by the calling user.
///
/// The bot starts `active` with a fresh [`BotId`]. Pass the request Valence
/// (`ctx.valence()`), never a System handle: the owner is taken from its actor.
///
/// # Errors
///
/// - [`BotError::NotAUser`] when the caller is not a signed-in user.
/// - [`BotError::InvalidHandle`] / [`BotError::InvalidProfile`] for bad input.
/// - [`BotError::GateNotInstalled`], [`BotError::CreateNotPermitted`], or
///   [`BotError::Gate`] when the host's gate refuses or fails.
/// - [`BotError::QuotaReached`] when the caller already owns
///   [`MAX_BOTS_PER_OWNER`] bots.
/// - [`BotError::HandleTaken`] with a free suggestion when another bot uses the
///   handle.
/// - [`BotError::Store`] on a storage failure.
pub async fn create_bot(valence: &Valence, input: NewBot<'_>) -> Result<Bot, BotError> {
    let result = create_bot_inner(valence, input).await;
    let id = result
        .as_ref()
        .ok()
        .and_then(|b| b.id())
        .and_then(|rid| BotId::parse(rid.id()).ok());
    record(Op::Create, result, id.as_ref())
}

async fn create_bot_inner(valence: &Valence, input: NewBot<'_>) -> Result<Bot, BotError> {
    let owner = caller_user(valence)?;
    let handle = BotHandle::parse(input.handle)?;
    let display_name = check_display_name(input.display_name)?;
    let description = check_description(input.description)?;
    require_create_permission(valence).await?;
    if list_my_bots(valence).await?.len() >= MAX_BOTS_PER_OWNER {
        return Err(BotError::QuotaReached {
            limit: MAX_BOTS_PER_OWNER,
        });
    }

    if handle_key_taken(valence, &handle.key()).await? {
        let suggestion = first_free(valence, handle).await.ok();
        return Err(BotError::HandleTaken { suggestion });
    }

    let id = BotId::new_v4();
    let owner_ref = RecordId::new("user", &owner);
    let now = Utc::now();
    let row = Bot::new(
        Some(owner_ref.clone()),
        BotOwnerKind::User,
        Some(owner_ref),
        handle.as_str().to_string(),
        handle.key(),
        display_name,
        description,
        BotStatus::Active,
        None,
        now,
        now,
    )
    .map_err(|_| BotError::Store)?;
    Bot::upsert(
        id.as_str(),
        row,
        valence,
        valence::use_!(r"When you **create a bot account**, we **save its profile**: the handle and display name you chose, the description, and that **you own it**. You see this on your bots page, and the platform uses the owner link to decide who may manage the bot."),
    )
    .await
    .map_err(|e| match e {
        valence::Error::Privacy(_) => BotError::CreateNotPermitted,
        _ => BotError::Store,
    })
}

/// Suggest a free handle built from free text such as a display name.
///
/// `"Spectra Bot"` becomes `spectra-bot`, or `spectra-2-bot` when that is taken.
///
/// # Errors
///
/// [`BotError::NotAUser`], the gate errors from [`create_bot`],
/// [`BotError::InvalidHandle`] when nothing usable is left after normalizing,
/// [`BotError::HandleTaken`] when every candidate is taken, or
/// [`BotError::Store`].
pub async fn suggest_bot_handle(valence: &Valence, wanted: &str) -> Result<BotHandle, BotError> {
    caller_user(valence)?;
    require_create_permission(valence).await?;
    let handle = BotHandle::normalize(wanted)?;
    first_free(valence, handle).await
}

/// Load one bot the caller may see: its own, or any bot when the gate grants
/// manage-any.
///
/// # Errors
///
/// [`BotError::NotAUser`]; [`BotError::NotFound`] when the bot does not exist
/// or the caller may not see it; [`BotError::Store`].
pub async fn get_bot(valence: &Valence, id: &BotId) -> Result<Bot, BotError> {
    caller_user(valence)?;
    load(valence, id).await
}

async fn load(valence: &Valence, id: &BotId) -> Result<Bot, BotError> {
    Bot::get(
        id.as_str(),
        valence,
        valence::use_!(r"On the **bot account** pages, we **load one bot's profile and status** so its owner (or a platform administrator) can see it and act on it. Anyone else gets **not found**, as if the bot did not exist."),
    )
    .await
    .map_err(|e| match e {
        // A deleted bot stays invisible while its deletion run finishes.
        valence::Error::PendingDeletion(_) => BotError::NotFound,
        _ => BotError::Store,
    })?
    .ok_or(BotError::NotFound)
}

/// The calling user's bots, oldest first (ties by handle).
///
/// # Errors
///
/// [`BotError::NotAUser`] or [`BotError::Store`].
pub async fn list_my_bots(valence: &Valence) -> Result<Vec<Bot>, BotError> {
    let owner = caller_user(valence)?;
    let bots = Bot::get_from_user_id(
        &owner,
        valence,
        valence::use_!(r"On **your bots** page, we **list the bot accounts you own** with their handle, display name, and status, and **show them to you**. Other people's bots are never included."),
    )
    .await
    .map_err(|_| BotError::Store)?;
    // Queries return rows whose deletion is still running; `Bot::get` hides
    // them, so the list must too.
    let mut visible = Vec::with_capacity(bots.len());
    for bot in bots {
        let Some(rid) = bot.id() else { continue };
        let bare = valence::extract_id_from_record(rid).unwrap_or_else(|_| rid.id().to_string());
        match OwnershipService::pending_deletion_gate("bot", &bare, valence).await {
            Ok(()) => visible.push(bot),
            Err(valence::Error::PendingDeletion(_)) => {}
            Err(_) => return Err(BotError::Store),
        }
    }
    let mut bots = visible;
    // Timestamps are stored at second precision; the handle breaks ties.
    bots.sort_by(|a, b| (a.created_at(), a.handle()).cmp(&(b.created_at(), b.handle())));
    Ok(bots)
}

/// Edit a bot's display name or description. The handle and owner never change.
///
/// # Errors
///
/// [`BotError::NotAUser`], [`BotError::NotFound`], [`BotError::InvalidProfile`],
/// [`BotError::Forbidden`], or [`BotError::Store`].
pub async fn update_bot(
    valence: &Valence,
    id: &BotId,
    update: BotProfileUpdate<'_>,
) -> Result<Bot, BotError> {
    let result = update_bot_inner(valence, id, update).await;
    record(Op::Update, result, Some(id))
}

async fn update_bot_inner(
    valence: &Valence,
    id: &BotId,
    update: BotProfileUpdate<'_>,
) -> Result<Bot, BotError> {
    caller_user(valence)?;
    let display_name = update.display_name.map(check_display_name).transpose()?;
    let description = update.description.map(check_description).transpose()?;
    let bot = load(valence, id).await?;
    let mut edit = bot.get_mutable(
        valence,
        valence::use_!(r"When the owner **edits a bot account**, we **save the new display name or description** they typed. The owner sees the change on the bot's page, and the bot's actions show the new name."),
    );
    if let Some(name) = display_name {
        edit = edit.set_display_name(name).map_err(|_| BotError::Store)?;
    }
    match description {
        Some(Some(text)) => edit = edit.set_description(text).map_err(|_| BotError::Store)?,
        Some(None) => edit = edit.clear_description(),
        None => {}
    }
    edit.set_updated_at(Utc::now())
        .map_err(|_| BotError::Store)?
        .commit()
        .await
        .map_err(|e| write_error(&e))
}

/// Suspend an active bot. A suspended bot keeps its profile but must not act;
/// token checks (added with bot tokens) refuse it.
///
/// # Errors
///
/// [`BotError::InvalidTransition`] when already suspended, plus the errors of
/// [`update_bot`].
pub async fn suspend_bot(valence: &Valence, id: &BotId) -> Result<Bot, BotError> {
    let result = set_status(valence, id, BotStatus::Suspended).await;
    record(Op::Suspend, result, Some(id))
}

/// Resume a suspended bot.
///
/// # Errors
///
/// [`BotError::InvalidTransition`] when already active, plus the errors of
/// [`update_bot`].
pub async fn resume_bot(valence: &Valence, id: &BotId) -> Result<Bot, BotError> {
    let result = set_status(valence, id, BotStatus::Active).await;
    record(Op::Resume, result, Some(id))
}

async fn set_status(valence: &Valence, id: &BotId, to: BotStatus) -> Result<Bot, BotError> {
    caller_user(valence)?;
    let bot = load(valence, id).await?;
    let next = transition(bot.status(), to)?;
    let now = Utc::now();
    let edit = bot
        .get_mutable(
            valence,
            valence::use_!(r"When the owner **suspends or resumes a bot account**, we **save its new status and when it was suspended**. The owner sees the status on the bot's page, and a suspended bot is refused when it tries to act."),
        )
        .set_status(next.clone())
        .map_err(|_| BotError::Store)?;
    let edit = if next == BotStatus::Suspended {
        edit.set_suspended_at(now).map_err(|_| BotError::Store)?
    } else {
        edit.clear_suspended_at()
    };
    edit.set_updated_at(now)
        .map_err(|_| BotError::Store)?
        .commit()
        .await
        .map_err(|e| write_error(&e))
}

/// Delete a bot with the standard Valence delete.
///
/// The bot disappears from reads right away. Valence then removes it, and anything
/// that cascades from it, in the deletion run started by the host's deletion
/// dispatcher. Hosts register one at boot (valence-platform's
/// `register_deletion_dispatch`, which runs the Chronon deletion orchestrator);
/// without it the bot stays hidden but is never purged.
///
/// # Errors
///
/// [`BotError::NotAUser`], [`BotError::NotFound`], [`BotError::Forbidden`], or
/// [`BotError::Store`] (including a host with no deletion dispatcher).
pub async fn delete_bot(valence: &Valence, id: &BotId) -> Result<(), BotError> {
    let result = delete_bot_inner(valence, id).await;
    record(Op::Delete, result, Some(id))
}

async fn delete_bot_inner(valence: &Valence, id: &BotId) -> Result<(), BotError> {
    caller_user(valence)?;
    load(valence, id).await?;
    Bot::delete(
        id.as_str(),
        valence,
        valence::use_!(r"When the owner **deletes a bot account**, we **remove the bot and everything attached to it** so it can no longer act and none of its data stays behind."),
    )
    .await
    .map_err(|e| write_error(&e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transition_table_happy() {
        assert!(matches!(
            transition(&BotStatus::Active, BotStatus::Suspended),
            Ok(BotStatus::Suspended)
        ));
        assert!(matches!(
            transition(&BotStatus::Suspended, BotStatus::Active),
            Ok(BotStatus::Active)
        ));
    }

    #[test]
    fn transition_table_sad() {
        assert!(matches!(
            transition(&BotStatus::Active, BotStatus::Active),
            Err(BotError::InvalidTransition {
                from: BotStatus::Active
            })
        ));
        assert!(matches!(
            transition(&BotStatus::Suspended, BotStatus::Suspended),
            Err(BotError::InvalidTransition {
                from: BotStatus::Suspended
            })
        ));
    }

    #[test]
    fn profile_checks_sad() {
        assert!(matches!(
            check_display_name("   "),
            Err(BotError::InvalidProfile {
                field: "display_name"
            })
        ));
        assert!(matches!(
            check_display_name(&"x".repeat(81)),
            Err(BotError::InvalidProfile {
                field: "display_name"
            })
        ));
        assert!(matches!(
            check_description(Some(&"x".repeat(501))),
            Err(BotError::InvalidProfile {
                field: "description"
            })
        ));
    }

    #[test]
    fn profile_checks_happy() {
        assert_eq!(
            check_display_name("  Spectra agent ").ok().as_deref(),
            Some("Spectra agent")
        );
        assert!(matches!(check_description(Some("  ")), Ok(None)));
        assert_eq!(
            check_description(Some(" reads metrics "))
                .ok()
                .flatten()
                .as_deref(),
            Some("reads metrics")
        );
    }
}
